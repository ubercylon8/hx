from hx.checks import base


class SecurityHeaders:
    id, version, klass = "hx.passive.security-headers", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.inconclusive("not implemented yet")
