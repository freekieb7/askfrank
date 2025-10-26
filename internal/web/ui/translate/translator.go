package translate

import "github.com/freekieb7/askfrank/internal/i18n"

type Translator struct {
	Translator *i18n.Translator
	Language   i18n.Language
}

func (t *Translator) T(key string) string {
	return t.Translator.T(t.Language, key)
}
