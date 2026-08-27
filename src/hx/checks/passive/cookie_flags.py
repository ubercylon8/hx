from hx.checks import base


class CookieFlags:
    id, version, klass = "hx.passive.cookie-flags", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.inconclusive("not implemented yet")
