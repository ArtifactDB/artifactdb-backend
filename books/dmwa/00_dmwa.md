---
title: Data management with ArtifactDB
subtitle: Technical Design & Usage
author: [Sébastien Lelong / DSSC]
date: "2022-12-14"
subject: "Cloud-based data management"
keywords: [API, ArtifactDB, cloud, backend]
book: true
classoption: [oneside]
titlepage: true,
titlepage-logo: "cover.png"
logo-width: 380px
titlepage-rule-height: 24
titlepage-rule-color: "444444"
titlepage-text-color: "000000"
colorlinks: true
toc-own-page: true
toc: true
pandoc-options:
  -  --filter=pandoc-include

---

# Acknowledgments

First things first, let's go over the team and other contributors behind these backend systems:

TODO

!include ../../docs/intro.md

# Usage

TODO: REST API and admin shell

!include`incrementSection=1` ../../docs/usage/upload.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/extrameta.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/fetch.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/search.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/gprns.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/projects.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/index.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/permissions.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/schemas.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/sequences.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/plugins.md

\pagebreak

!include`incrementSection=1` ../../docs/usage/config.md

\pagebreak



# Design

!include`incrementSection=1` ../../docs/design/architecture.md

\pagebreak

!include`incrementSection=1` ../../docs/design/config.md

\pagebreak

!include`incrementSection=1` ../../docs/design/schemas.md

\pagebreak

!include`incrementSection=1` ../../docs/design/storages.md

\pagebreak

!include`incrementSection=1` ../../docs/design/identifiers.md

\pagebreak

!include`incrementSection=1` ../../docs/design/auth.md

\pagebreak

!include`incrementSection=1` ../../docs/design/backend.md

\pagebreak

!include`incrementSection=1` ../../docs/design/sequences.md

\pagebreak

!include`incrementSection=1` ../../docs/design/events.md

\pagebreak

!include`incrementSection=1` ../../docs/design/links.md

\pagebreak

!include`incrementSection=1` ../../docs/design/redirections.md

\pagebreak

!include`incrementSection=1` ../../docs/design/plugins.md

\pagebreak

!include`incrementSection=1` ../../docs/design/jsondiff.md

\pagebreak

!include`incrementSection=1` ../../docs/design/antipatterns.md

\pagebreak


# Conclusion

Wow that was great.
