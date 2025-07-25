package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Translations map[string]string

type I18n struct {
	translations map[string]Translations
	defaultLang  string
}

func New(defaultLang string) *I18n {
	return &I18n{
		translations: make(map[string]Translations),
		defaultLang:  defaultLang,
	}
}

func (i *I18n) LoadTranslations(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) == ".json" {
			lang := filepath.Base(path)
			lang = lang[:len(lang)-5] // Remove .json extension

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

			i.translations[lang] = translations
		}

		return nil
	})
}

func (i *I18n) T(lang, key string) string {
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

func (i *I18n) GetAvailableLanguages() []string {
	var langs []string
	for lang := range i.translations {
		langs = append(langs, lang)
	}
	return langs
}
