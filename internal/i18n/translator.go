package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Language string

const (
	NL Language = "nl"
	EN Language = "en"
)

func (l Language) String() string {
	return string(l)
}

func ParseLanguage(lang string) (Language, error) {
	switch lang {
	case "nl":
		return NL, nil
	case "en":
		return EN, nil
	default:
		return "", fmt.Errorf("unsupported language: %s", lang)
	}
}

type Translations map[string]string

type Translator struct {
	translations map[Language]Translations
	defaultLang  Language
}

func NewTranslator(defaultLang Language) Translator {
	return Translator{
		translations: make(map[Language]Translations),
		defaultLang:  defaultLang,
	}
}

func (i *Translator) LoadTranslations() error {
	return filepath.Walk("internal/i18n/translations", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) == ".json" {
			langName := filepath.Base(path)
			langName = langName[:len(langName)-5] // Remove .json extension

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() {
				if err := file.Close(); err != nil {
					fmt.Printf("Failed to close file %s: %v\n", path, err)
				}
			}()

			var translations Translations
			if err := json.NewDecoder(file).Decode(&translations); err != nil {
				return err
			}

			lang, err := ParseLanguage(langName)
			if err != nil {
				return fmt.Errorf("failed to parse language %s: %w", langName, err)
			}

			i.translations[lang] = translations
		}

		return nil
	})
}

func (i *Translator) T(lang Language, key string) string {
	if translations, ok := i.translations[lang]; ok {
		if translation, ok := translations[key]; ok {
			return translation
		}
	}

	// Fallback to default language
	if lang != i.defaultLang {
		if translations, ok := i.translations[i.defaultLang]; ok {
			if translation, ok := translations[key]; ok {
				return translation
			}
		}
	}

	// Return key if no translation found
	return fmt.Sprintf("[missing: %s]", key)
}

func (i *Translator) GetAvailableLanguages() []Language {
	var langs []Language
	for lang := range i.translations {
		langs = append(langs, lang)
	}
	return langs
}
