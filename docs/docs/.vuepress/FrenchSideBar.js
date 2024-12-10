
export default {
    '/fr/': {
        lang: 'fr-FR',
        title: 'Capierre Documentation',
        description: 'Capierre Documentation',

        sidebar: [
          {
            children: [
              '/fr/Introduction.md',
              '/fr/Comment_utiliser.md'
            ],
          },
          {
            collapsible: true,
            text: '🛠️ Tool',
            children: [
              '/fr/tool/Tool_Documentation.md',
            ]
          },
        ],
    },
}
