# Corpus Seeds

The Go fuzz target embeds the initial seed corpus in code so `go test -fuzz`
can run without external corpus setup. Persistent fuzz discoveries should be
copied here before publication.
