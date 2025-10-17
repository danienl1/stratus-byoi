package main

import (
	"errors"
	"log"
	"os"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/spf13/cobra"
)

var flagForceCleanup bool
var flagCleanupAll bool
var cleanupCustomTerraformDir string

func buildCleanupCmd() *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:                   "cleanup [attack-technique-id]... | --all",
		Aliases:               []string{"clean"},
		Short:                 "Cleans up any leftover infrastructure or configuration from a TTP.",
		Example:               "stratus cleanup aws.defense-evasion.cloudtrail-stop\nstratus cleanup --all",
		DisableFlagsInUseLine: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && flagCleanupAll {
				if !flagCleanupAll {
					return errors.New("pass the ID of the technique to clean up, or --all")
				}
				return nil
			}

			// Ensure the technique IDs are valid
			_, err := resolveTechniques(args)

			return err
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return getTechniquesCompletion(toComplete), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				techniques, _ := resolveTechniques(args)
				doCleanupCmd(techniques)
				return nil
			} else if flagCleanupAll {
				// clean up all techniques that are not in the COLD state
				doCleanupAllCmd()
				return nil
			} else {
				return errors.New("pass the ID of the technique to clean up, or --all")
			}
		},
	}
	cleanupCmd.Flags().BoolVarP(&flagForceCleanup, "force", "f", false, "Force cleanup even if the technique is already COLD")
	cleanupCmd.Flags().BoolVarP(&flagCleanupAll, "all", "", false, "Clean up all techniques that are not in COLD state")
	cleanupCmd.Flags().StringVarP(&cleanupCustomTerraformDir, "terraform-dir", "", "", "Path to a custom Terraform directory containing your own infrastructure prerequisites. When specified, this overrides the embedded Terraform code.")
	return cleanupCmd
}

func doCleanupCmd(techniques []*stratus.AttackTechnique) {
	workerCount := len(techniques)
	techniquesChan := make(chan *stratus.AttackTechnique, workerCount)
	errorsChan := make(chan error, workerCount)
	for i := 0; i < workerCount; i++ {
		go cleanupCmdWorker(techniquesChan, errorsChan)
	}
	for i := range techniques {
		techniquesChan <- techniques[i]
	}
	close(techniquesChan)

	hadError := handleErrorsChannel(errorsChan, workerCount)
	doStatusCmd(techniques)
	if hadError {
		os.Exit(1)
	}
}

func cleanupCmdWorker(techniques <-chan *stratus.AttackTechnique, errors chan<- error) {
	for technique := range techniques {
		options := runner.RunnerOptions{
			Force:              flagForceCleanup,
			CustomTerraformDir: cleanupCustomTerraformDir,
		}
		stratusRunner := runner.NewRunner(technique, options)
		err := stratusRunner.CleanUp()
		errors <- err
	}
}

func doCleanupAllCmd() {
	log.Println("Cleaning up all techniques that have been warmed-up or detonated")
	availableTechniques := stratus.GetRegistry().ListAttackTechniques()
	doCleanupCmd(availableTechniques)
}
