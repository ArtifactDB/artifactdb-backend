# requires pandoc-include: pip install pandoc-include
pandoc 00_dmwa.md --from markdown --template "../templates/eisvogel.tex" --listings --top-level-division="chapter" --filter pandoc-include -o "dmwa.pdf" 
