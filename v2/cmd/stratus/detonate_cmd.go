package main

import (
	"errors"
	"os"
	"strings"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"

	"github.com/spf13/cobra"
)

var detonateForce bool
var detonateCleanup bool
var detonateNoWarmup bool
var detonateOutputsFile string
var detonateCustomTerraformDir string

func buildDetonateCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
		Use:   "detonate attack-technique-id [attack-technique-id]...",
		Short: "Detonate one or multiple attack techniques",
		Example: strings.Join([]string{
			"stratus detonate aws.defense-evasion.cloudtrail-stop",
			"stratus detonate aws.defense-evasion.cloudtrail-stop --cleanup",
			"stratus detonate aws.persistence.iam-backdoor-user --no-warmup --outputs-file terraform.outputs.json",
		}, "\n"),
		DisableFlagsInUseLine: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.Help()
				os.Exit(0)
			}
			return nil
		},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return getTechniquesCompletion(toComplete), cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doDetonateCmd(techniques)
		},
	}
	detonateCmd.Flags().BoolVarP(&detonateCleanup, "cleanup", "", false, "Clean up the infrastructure that was spun up as part of the technique prerequisites")
	detonateCmd.Flags().BoolVarP(&detonateNoWarmup, "no-warmup", "", false, "Do not spin up prerequisite infrastructure or configuration. When using this, you are responsible for creating the infrastructure prerequisites. Requires that you specify the path to a terraform output file, see --outputs-file.")
	detonateCmd.Flags().StringVarP(&detonateOutputsFile, "outputs-file", "", "", "Path to a JSON file containing terraform outputs. Required when using --no-warmup.")
	detonateCmd.Flags().StringVarP(&detonateCustomTerraformDir, "terraform-dir", "", "", "Path to a custom Terraform directory containing your own infrastructure prerequisites. When specified, this overrides the embedded Terraform code.")
	detonateCmd.Flags().BoolVarP(&detonateForce, "force", "f", false, "Force detonation in cases where the technique is not idempotent and has already been detonated")

	return detonateCmd
}
func doDetonateCmd(techniques []*stratus.AttackTechnique) {
	VerifyPlatformRequirements(techniques)
	workerCount := len(techniques)
	techniquesChan := make(chan *stratus.AttackTechnique, workerCount)
	errorsChan := make(chan error, workerCount)

	// Create workers
	for i := 0; i < workerCount; i++ {
		go detonateCmdWorker(techniquesChan, errorsChan)
	}

	// Send attack techniques to detonate
	for i := range techniques {
		techniquesChan <- techniques[i]
	}
	close(techniquesChan)

	if hadError := handleErrorsChannel(errorsChan, workerCount); hadError {
		os.Exit(1)
	}
}

func detonateCmdWorker(techniques <-chan *stratus.AttackTechnique, errors chan<- error) {
	for technique := range techniques {
		options := runner.RunnerOptions{
			Force:              detonateForce,
			NoWarmup:           detonateNoWarmup,
			OutputsFile:        detonateOutputsFile,
			CustomTerraformDir: detonateCustomTerraformDir,
		}
		stratusRunner := runner.NewRunner(technique, options)
		detonateErr := stratusRunner.Detonate()
		if detonateCleanup {
			cleanupErr := stratusRunner.CleanUp()
			errors <- utils.CoalesceErr(detonateErr, cleanupErr)
		} else {
			errors <- detonateErr
		}
	}
}
