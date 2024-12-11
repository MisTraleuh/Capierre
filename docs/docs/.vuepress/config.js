/****************************
*        CONFIGURATION      *
****************************/
import defaultTheme from '@vuepress/theme-default';
import searchPlugin from '@vuepress/plugin-search';
import { defineUserConfig } from '@vuepress/cli';
import { viteBundler } from '@vuepress/bundler-vite';

/****************************
*            I18N           *
****************************/
import EnglishSideBar from './EnglishSideBar'
import FrenchSideBar from './FrenchSideBar'

export default defineUserConfig({
  base: '/',
  title: 'Capierre Documentation',
  description: ' ',
  head: [
    ['link', { rel: 'icon', href: '/logo.png' }],
  ],
  port: 14242,

  bundler: viteBundler({
    viteOptions: {},
    vuePluginOptions: {},
  }),

  locales: {
    '/': {
      lang: 'en-US',
    },
    '/fr/': {
      lang: 'Français',
    },
  },

  theme : defaultTheme({
    logo: '/logo.png',
    repo: 'https://github.com/MisTraleuh/Capierre',

    contributors: false,
    lastUpdated: false,
    editLink: false,

    navbar:  [
      {
        text: 'Buy me a coffee ☕',
        link: 'https://www.buymeacoffee.com/mistrale',
      },
    ],

    locales: {
      /*******************************
      *           ENGLISH            * 
      *******************************/
      '/': EnglishSideBar["/"],
      /*******************************
      *           FRANCAIS           * 
      *******************************/
      '/fr/': FrenchSideBar["/fr/"],
    }
  }),
  plugins: [
      searchPlugin({
      // options
      }),
  ],
})
