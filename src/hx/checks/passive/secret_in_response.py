from hx.checks import base


class SecretInResponse:
    id, version, klass = "hx.passive.secret-in-response", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.inconclusive("not implemented yet")
