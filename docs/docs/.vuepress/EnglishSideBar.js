
export default {
    '/':
      {
        lang: 'en-US',
        title: 'Capierre Documentation',
        description: 'Capierre Documentation',
        sidebar: [
          {
            children: [
              '/en/Introduction.md',
              '/en/How_to_use.md',
            ],
          },
          {
            collapsible: true,
            text: '🛠️ Tool',
            children: [
              '/en/tool/Tool_Documentation.md',
              '/en/tool/Basic_concept.md',
              '/en/tool/Functioning_of_Capierre_tool.md',
            ]
          },
        ],
      },
}
