package organization

import betterauth "github.com/eadwinCode/better-auth-go"

func (instance *runtime) plugin() betterauth.Plugin {
	return betterauth.Plugin{
		ID:     "organization",
		Schema: instance.schema,
	}
}
