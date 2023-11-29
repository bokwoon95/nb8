package notebrewcli

type Cmd interface {
	Run() error
}
