"""Entry point selection across Python's old mapping and newer selectable APIs."""
from importlib.metadata import entry_points


def group_entry_points(group):
    points = entry_points()
    if hasattr(points, 'select'):
        return points.select(group=group)
    return points.get(group, ())
