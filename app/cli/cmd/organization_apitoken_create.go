//
// Copyright 2024-2025 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/chainloop-dev/chainloop/app/cli/internal/action"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func newAPITokenCreateCmd() *cobra.Command {
	var (
		description, name, projectName string
		expiresIn                      time.Duration
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an API token",
		RunE: func(cmd *cobra.Command, args []string) error {
			var duration *time.Duration
			if expiresIn != 0 {
				duration = &expiresIn
			}

			res, err := action.NewAPITokenCreate(actionOpts).Run(context.Background(), name, description, projectName, duration)
			if err != nil {
				return fmt.Errorf("creating API token: %w", err)
			}

			if flagOutputFormat == "token" {
				fmt.Print(res.JWT)
				return nil
			}

			return encodeOutput(res, apiTokenItemTableOutput)
		},
	}

	cmd.Flags().StringVar(&description, "description", "", "API token description")
	cmd.Flags().DurationVar(&expiresIn, "expiration", 0, "optional API token expiration, in hours i.e 1h, 24h, 178h (week), ...")
	cmd.Flags().StringVar(&name, "name", "", "token name")
	// Override default output flag
	cmd.InheritedFlags().StringVarP(&flagOutputFormat, "output", "o", "table", "output format, valid options are table, json, token")
	err := cmd.MarkFlagRequired("name")
	cobra.CheckErr(err)
	cmd.Flags().StringVar(&projectName, "project", "", "project name used to scope the token, if not set the token will be created at the organization level")

	return cmd
}

func apiTokenItemTableOutput(token *action.APITokenItem) error {
	return apiTokenListTableOutput([]*action.APITokenItem{token})
}

func apiTokenListTableOutput(tokens []*action.APITokenItem) error {
	if len(tokens) == 0 {
		fmt.Println("there are no API tokens in this org")
		return nil
	}

	t := newTableWriter()

	t.AppendHeader(table.Row{"ID", "Name", "Scope", "Description", "Created At", "Expires At", "Revoked At", "Last used at"})
	for _, p := range tokens {
		r := table.Row{p.ID, p.Name, p.ScopedEntity.String(), p.Description, p.CreatedAt.Format(time.RFC822)}
		if p.ExpiresAt != nil {
			r = append(r, p.ExpiresAt.Format(time.RFC822))
		} else {
			r = append(r, "")
		}

		if p.RevokedAt != nil {
			r = append(r, p.RevokedAt.Format(time.RFC822))
		} else {
			r = append(r, "")
		}

		if p.LastUsedAt != nil {
			r = append(r, p.LastUsedAt.Format(time.RFC822))
		}

		t.AppendRow(r)
	}
	t.Render()

	if len(tokens) == 1 && tokens[0].JWT != "" {
		// Output the token too
		fmt.Printf("\nSave the following token since it will not printed again: \n\n %s\n\n", tokens[0].JWT)
	}

	return nil
}
