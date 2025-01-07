
export default {
    '/fr/': {
        lang: 'fr-FR',
        title: 'Capierre Documentation',
        description: 'Capierre Documentation',

        sidebar: [
          {
            children: [
              '/fr/Introduction.md',
              '/fr/Comment_utiliser.md',
              '/fr/Pour_qui_quoi_comment.md',
            ],
          },
          {
            collapsible: true,
            text: '🛠️ Tool',
            children: [
              '/fr/tool/Tool_Documentation.md',
              '/fr/tool/Concept_de_base.md',
              '/fr/tool/Fonctionnement_du_tool_Capierre.md',
            ],
          },
          {
            collapsible: true,
            text: '🖥️ Gui',
            children: [
              '/fr/gui/Guide_GUI.md',
              '/fr/gui/Installation_GUI.md',
              '/fr/gui/Presentation_GUI.md',
              '/fr/gui/Utilisation_GUI.md',
              '/fr/gui/FAQ_GUI.md',
            ],
          },
        ],
    },
}
