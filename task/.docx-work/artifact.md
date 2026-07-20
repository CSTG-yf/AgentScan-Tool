# Template execution contract

- Reference: `F:\agentscan2\task\AI_Agent安全防御闭环_项目实施计划书_v1.1_协作分工版.docx`
- SHA-256: `ED5CE91C2ED5421AF5A390C9C59557CB29E5F484954F5CFA84D6D0C647C547D9`
- Evidence: `task/.docx-work/template-style-evidence.json`; section audit captured in task log.
- Page render: unavailable because LibreOffice/soffice is not installed. Structural QA is required.
- Sections: 1. US Letter portrait, 8.5 x 11 in; margins 1 in on all sides; one column.
- Header: linked/default empty. Footer: source footer retained. No different-first-page behavior.
- Typography: source styles are authoritative. Body uses Normal; section titles use Heading 1;
  module titles use Heading 2; bullets use List Bullet. Title block is four Normal paragraphs
  with direct run formatting and must be edited in place to retain formatting.
- Content pattern: four-paragraph title block; Heading 1 sections; concise body/bullets; one lead
  callout table; one 9x5 module table; eight 1x1 output callouts; one 7x4 branch table; one 5x5
  weekly plan; one 8x2 task-card definition table; one 8x5 first-task table.
- Table pattern: retain all 14 source tables, widths, borders, cell margins, fills and alignment.
  Only cell text is editable. Header rows and all geometry are preserve-only.
- Slot map: all 66 body paragraphs and all table cell text are editable; section count, styles,
  table count/geometry, header/footer, theme, numbering, relationships and package metadata are
  preserve-only. Paragraph positions and styles remain unchanged.
- Package preservation: preserve styles.xml, numbering.xml, theme, settings, relationships,
  headers/footers and all table properties. Only text nodes in document.xml should materially change.
- Fidelity gates: reference hash must remain unchanged; final keeps one section, 66 paragraphs,
  14 tables with row/column dimensions `[1x1,9x5,1x1*8,7x4,5x5,8x2,8x5]`; source styles and
  page geometry remain intact; no empty required slot; no unexplained package-part loss.
