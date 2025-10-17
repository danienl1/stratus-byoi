package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/google/uuid"
)

const EnvVarStratusRedTeamDetonationId = "STRATUS_RED_TEAM_DETONATION_ID"

type RunnerOptions struct {
	Force              bool
	NoWarmup           bool
	OutputsFile        string
	CustomTerraformDir string
}

type runnerImpl struct {
	Technique           *stratus.AttackTechnique
	TechniqueState      stratus.AttackTechniqueState
	TerraformDir        string
	Options             RunnerOptions
	TerraformManager    TerraformManager
	StateManager        state.StateManager
	ProviderFactory     stratus.CloudProviders
	UniqueCorrelationID uuid.UUID
	Context             context.Context
}

type Runner interface {
	WarmUp() (map[string]string, error)
	Detonate() error
	Revert() error
	CleanUp() error
	GetState() stratus.AttackTechniqueState
	GetUniqueExecutionId() string
}

var _ Runner = &runnerImpl{}

func NewRunner(technique *stratus.AttackTechnique, options RunnerOptions) Runner {
	return NewRunnerWithContext(context.Background(), technique, options)
}

func NewRunnerWithContext(ctx context.Context, technique *stratus.AttackTechnique, options RunnerOptions) Runner {
	stateManager := state.NewFileSystemStateManager(technique)

	var correlationId = uuid.New()
	var err error
	if grimoireDetonationId := os.Getenv("STRATUS_RED_TEAM_DETONATION_ID"); grimoireDetonationId != "" {
		log.Println("STRATUS_RED_TEAM_DETONATION_ID is set, using it as the correlation ID")
		correlationId, err = uuid.Parse(grimoireDetonationId)
		if err != nil {
			log.Println("STRATUS_RED_TEAM_DETONATION_ID is not a valid UUID, falling back to a randomly-generated one: " + err.Error())
			correlationId = uuid.New()
		}
	}

	runner := &runnerImpl{
		Technique:           technique,
		Options:             options,
		StateManager:        stateManager,
		UniqueCorrelationID: correlationId,
		TerraformManager: NewTerraformManagerWithContext(
			ctx, filepath.Join(stateManager.GetRootDirectory(), "terraform"), useragent.GetStratusUserAgentForUUID(correlationId),
		),
		Context: ctx,
	}
	runner.initialize()

	return runner
}

func (m *runnerImpl) initialize() {
	// Use custom Terraform directory if specified, otherwise use the default state directory
	if m.Options.CustomTerraformDir != "" {
		// Convert relative paths to absolute paths to ensure they work regardless of working directory
		if !filepath.IsAbs(m.Options.CustomTerraformDir) {
			absPath, err := filepath.Abs(m.Options.CustomTerraformDir)
			if err != nil {
				log.Printf("Warning: unable to resolve absolute path for custom Terraform directory %s: %v", m.Options.CustomTerraformDir, err)
				m.TerraformDir = m.Options.CustomTerraformDir
			} else {
				m.TerraformDir = absPath
			}
		} else {
			m.TerraformDir = m.Options.CustomTerraformDir
		}
	} else {
		m.TerraformDir = filepath.Join(m.StateManager.GetRootDirectory(), m.Technique.ID)
	}
	m.TechniqueState = m.StateManager.GetTechniqueState()
	if m.TechniqueState == "" {
		m.TechniqueState = stratus.AttackTechniqueStatusCold
	}
	m.ProviderFactory = stratus.CloudProvidersImpl{UniqueCorrelationID: m.UniqueCorrelationID}
}

func (m *runnerImpl) WarmUp() (map[string]string, error) {
	// No prerequisites to spin-up
	if m.Technique.PrerequisitesTerraformCode == nil && m.Options.CustomTerraformDir == "" {
		return map[string]string{}, nil
	}

	if m.Options.NoWarmup {
		log.Println("Not warming up - --no-warmup was passed")
		return m.readTerraformOutputs()
	}

	// Only extract embedded Terraform if not using custom directory
	if m.Options.CustomTerraformDir == "" {
		err := m.StateManager.ExtractTechnique()
		if err != nil {
			return nil, errors.New("unable to extract Terraform file: " + err.Error())
		}
	} else {
		log.Println("Using custom Terraform directory: " + m.Options.CustomTerraformDir)
	}

	// We don't want to warm up the technique
	var willWarmUp = true

	// Technique is already warm
	if m.TechniqueState == stratus.AttackTechniqueStatusWarm && !m.Options.Force {
		log.Println("Not warming up - " + m.Technique.ID + " is already warm. Use --force to force")
		willWarmUp = false
	}

	if m.TechniqueState == stratus.AttackTechniqueStatusDetonated {
		log.Println(m.Technique.ID + " has been detonated but not cleaned up, not warming up as it should be warm already.")
		willWarmUp = false
	}

	if !willWarmUp {
		outputs, err := m.StateManager.GetTerraformOutputs()
		return outputs, err
	}

	log.Println("Warming up " + m.Technique.ID)
	outputs, err := m.TerraformManager.TerraformInitAndApply(m.TerraformDir)
	if err != nil {
		log.Println("Error during warm up. Cleaning up technique prerequisites with terraform destroy")
		_ = m.TerraformManager.TerraformDestroy(m.TerraformDir)
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, errors.New("unable to run terraform apply on prerequisite: " + errorMessageFromTerraformError(err))
	}

	// Persist outputs to disk (only for embedded Terraform, not custom directories)
	if m.Options.CustomTerraformDir == "" {
		err = m.StateManager.WriteTerraformOutputs(outputs)
	}
	m.setState(stratus.AttackTechniqueStatusWarm)

	if display, ok := outputs["display"]; ok {
		display := strings.ReplaceAll(display, "\\n", "\n")
		log.Println(display)
	}
	return outputs, err
}

func (m *runnerImpl) Detonate() error {
	willWarmUp := true
	var err error
	var outputs map[string]string

	// If the attack technique has already been detonated, make sure it's idempotent
	if m.GetState() == stratus.AttackTechniqueStatusDetonated {
		if !m.Technique.IsIdempotent && !m.Options.Force {
			return errors.New(m.Technique.ID + " has already been detonated and is not idempotent. " +
				"Revert it with 'stratus revert' before detonating it again, or use --force")
		}
		willWarmUp = false
	}

	if m.Technique.IsSlow {
		log.Println("Note: This is a slow attack technique, it might take a long time to warm up or detonate")
	}

	if willWarmUp {
		outputs, err = m.WarmUp()
	} else {
		// For custom Terraform directories, get outputs directly from Terraform
		if m.Options.CustomTerraformDir != "" {
			outputs, err = m.TerraformManager.TerraformOutput(m.TerraformDir)
		} else {
			outputs, err = m.StateManager.GetTerraformOutputs()
		}
	}

	if err != nil {
		return err
	}

	// Detonate
	err = m.Technique.Detonate(outputs, m.ProviderFactory)
	if err != nil {
		return errors.New("Error while detonating attack technique " + m.Technique.ID + ": " + err.Error())
	}
	m.setState(stratus.AttackTechniqueStatusDetonated)
	return nil
}

func (m *runnerImpl) Revert() error {
	if m.GetState() != stratus.AttackTechniqueStatusDetonated && !m.Options.Force {
		return errors.New(m.Technique.ID + " is not in DETONATED state and should not need to be reverted, use --force to force")
	}

	// For custom Terraform directories, get outputs directly from Terraform
	var outputs map[string]string
	var err error
	if m.Options.CustomTerraformDir != "" {
		outputs, err = m.TerraformManager.TerraformOutput(m.TerraformDir)
	} else {
		outputs, err = m.StateManager.GetTerraformOutputs()
	}
	if err != nil {
		return errors.New("unable to retrieve outputs of " + m.Technique.ID + ": " + err.Error())
	}

	log.Println("Reverting detonation of technique " + m.Technique.ID)

	if m.Technique.Revert != nil {
		err = m.Technique.Revert(outputs, m.ProviderFactory)
		if err != nil {
			return errors.New("unable to revert detonation of " + m.Technique.ID + ": " + err.Error())
		}
	}

	m.setState(stratus.AttackTechniqueStatusWarm)

	return nil
}

func (m *runnerImpl) CleanUp() error {
	// Has the technique already been cleaned up?
	if m.TechniqueState == stratus.AttackTechniqueStatusCold && !m.Options.Force {
		return errors.New(m.Technique.ID + " is already COLD and should already be clean, use --force to force cleanup")
	}

	log.Println("Cleaning up " + m.Technique.ID)

	// Revert detonation
	// For custom Terraform directories, always try to revert if there's a revert function
	// since we can't reliably track state across sessions
	shouldRevert := m.Technique.Revert != nil && (m.GetState() == stratus.AttackTechniqueStatusDetonated || m.Options.CustomTerraformDir != "")
	if shouldRevert {
		err := m.Revert()
		if err != nil {
			if m.Options.Force {
				log.Println("Warning: failed to revert detonation of " + m.Technique.ID + ". Ignoring and cleaning up anyway as --force was used.")
			} else {
				return errors.New("unable to revert detonation of " + m.Technique.ID + " before cleaning up (use --force to cleanup anyway): " + err.Error())
			}
		}
	}

	// Nuke prerequisites
	if (m.Technique.PrerequisitesTerraformCode != nil || m.Options.CustomTerraformDir != "") && !m.Options.NoWarmup {
		log.Println("Cleaning up technique prerequisites with terraform destroy")
		err := m.TerraformManager.TerraformDestroy(m.TerraformDir)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			return errors.New("unable to cleanup TTP prerequisites: " + errorMessageFromTerraformError(err))
		}
	}

	m.setState(stratus.AttackTechniqueStatusCold)

	// Only remove terraform directory if using embedded Terraform (not custom)
	if m.Options.CustomTerraformDir == "" {
		err := m.StateManager.CleanupTechnique()
		if err != nil {
			return errors.New("unable to remove technique directory " + m.TerraformDir + ": " + err.Error())
		}
	}

	return nil
}

func (m *runnerImpl) GetState() stratus.AttackTechniqueState {
	// For custom Terraform directories, we don't persist state to disk
	// So we need to determine the state differently
	if m.Options.CustomTerraformDir != "" {
		// For custom directories, we can't reliably track state across sessions
		// We'll assume COLD unless we're in the middle of a session
		if m.TechniqueState == "" {
			return stratus.AttackTechniqueStatusCold
		}
	}
	return m.TechniqueState
}

func (m *runnerImpl) setState(state stratus.AttackTechniqueState) {
	// For custom Terraform directories, we don't persist state to disk
	// The state is only tracked in memory for the current session
	if m.Options.CustomTerraformDir == "" {
		err := m.StateManager.SetTechniqueState(state)
		if err != nil {
			log.Println("Warning: unable to set technique state: " + err.Error())
		}
	}
	m.TechniqueState = state
}

// GetUniqueExecutionId returns an unique execution ID, unique for each runner instance
func (m *runnerImpl) GetUniqueExecutionId() string {
	return m.UniqueCorrelationID.String()
}

func (m *runnerImpl) readTerraformOutputs() (map[string]string, error) {
	if m.Options.OutputsFile == "" {
		return nil, errors.New("you must specify --outputs-file when using --no-warmup")
	}

	// Read the file
	bytes, err := ioutil.ReadFile(m.Options.OutputsFile)
	if err != nil {
		return nil, errors.New("unable to read terraform outputs file: " + err.Error())
	}

	// Unmarshal the JSON
	var outputs map[string]string
	err = json.Unmarshal(bytes, &outputs)
	if err != nil {
		return nil, errors.New("unable to parse terraform outputs file: " + err.Error())
	}

	return outputs, nil
}

// Utility function to display better error messages than the Terraform ones
func errorMessageFromTerraformError(err error) string {
	const MissingRegionErrorMessage = "The argument \"region\" is required, but no definition was found"

	if strings.Contains(err.Error(), MissingRegionErrorMessage) {
		return "unable to create attack technique prerequisites. Ensure you are authenticated against AWS and have the right permissions to run Stratus Red Team.\n" +
			"Stratus Red Team will display below the error that Terraform returned:\n" + err.Error()
	}

	return err.Error()
}
