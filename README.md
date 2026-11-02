# KMP-catalog

## Nós públicos

`seed-nodes.json` lista até 16 nós públicos (`IPv4:porta`) que rodam o
`deploy/kmp-seed` do repositório KMP. A promoção copia a lista para
`extensions["kmp.seed-nodes"]` do snapshot assinado, e os clientes adicionam
cada nó aos magnets como peer direto. Alterar o arquivo publica uma nova
sequência do catálogo, mesmo sem submissões pendentes.