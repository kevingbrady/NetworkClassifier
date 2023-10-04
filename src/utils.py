def pretty_time_delta(seconds):
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd %dh %dm %.2fs' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh %dm %.2fs' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm %.2fs' % (minutes, seconds)
    else:
        return '%.2fs' % seconds
