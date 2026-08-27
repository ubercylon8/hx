from hx.checks import base


class StackTrace:
    id, version, klass = "hx.passive.stack-trace", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.inconclusive("not implemented yet")
