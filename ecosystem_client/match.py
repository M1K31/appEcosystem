def matches_pattern(event_type: str, pattern: str) -> bool:
    """
    Decide whether an event type matches a subscription pattern.

    Supported patterns: "*" (everything), "prefix.*" (that namespace), or an exact
    event type.

    An empty event type or an empty pattern never matches. This is a guard, not a
    nicety: matches_pattern drives delivery routing, and "" previously matched the
    "*" subscription, so a malformed event with no type was fanned out to every
    wildcard subscriber in the ecosystem. Refusing to route it keeps a publisher bug
    from becoming everyone's problem.
    """
    if not event_type or not pattern:
        return False
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return event_type.startswith(pattern[:-2] + ".")
    return event_type == pattern
