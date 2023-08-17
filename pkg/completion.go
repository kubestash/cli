package pkg

import (
	"os"

	"github.com/spf13/cobra"
)

func NewCmdCompletion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:

$ source <(kubectl-stash completion bash)

# To load completions for each session, execute once:
Linux:
  $ kubectl-kubestash completion bash > /etc/bash_completion.d/kubectl-kubestash
MacOS:
  $ kubectl-kubestash completion bash > /usr/local/etc/bash_completion.d/kubectl-kubestash

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ kubectl-kubestash completion zsh > "${fpath[1]}/_kubectl-kubestash"

# You will need to start a new shell for this setup to take effect.

Fish:

$ kubectl-kubestash completion fish | source

# To load completions for each session, execute once:
$ kubectl-kubestash completion fish > ~/.config/fish/completions/kubectl-kubestash.fish
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
			return nil
		},
	}
	return cmd
}
