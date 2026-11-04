package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

func TestCLICommands(t *testing.T) {
	tests := []struct {
		name, command, config string
		args                  []string
		wantErr               bool
	}{
		{name: "serve", args: []string{"serve"}, command: "serve", config: "config.yaml"},
		{name: "update db", args: []string{"update-db", "-c", "custom.yaml"}, command: "update-db", config: "custom.yaml"},
		{name: "global config", args: []string{"--config", "custom.yaml", "serve"}, command: "serve", config: "custom.yaml"},
		{name: "no command", wantErr: true},
		{name: "old update command", args: []string{"update"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli CLI
			parser, err := kong.New(&cli)
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := parser.Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
			if err == nil && (ctx.Command() != tt.command || cli.Config != tt.config) {
				t.Fatalf("got command %q and config %q, want %q and %q", ctx.Command(), cli.Config, tt.command, tt.config)
			}
		})
	}
}
