import { createI18n } from 'vue-i18n'
import en from '../../../locales/en.json'

// This fork intentionally ignores previously persisted language selections.
const availableLocales = [{ key: 'en', label: 'English' }]
const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: { en }
})

export { availableLocales }
export default i18n
