package dns

type Config struct {
	Name string `config:"name"`

	Questions   []string `config:"questions" validate:"required"`
	NameServers []string `config:"nameservers" validate:"required"`
}

var defaultConfig = Config{
	Name: "dns",
}
