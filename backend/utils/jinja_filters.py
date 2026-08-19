# Jinja2 template filters
from jinja2 import contextfilter, Markup
from datetime import datetime
import hashlib
import html

@contextfilter
def format_datetime(context, value, format='%Y-%m-%d %H:%M:%S'):
    """Format datetime"""
    if value is None:
        return ''
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value
    return value.strftime(format)

@contextfilter
def user_display_name(context, user):
    """Get user display name from context"""
    if isinstance(user, dict):
        return user.get('username', user.get('email', 'Unknown'))
    return getattr(user, 'username', getattr(user, 'email', 'Unknown'))

@contextfilter
def truncate(context, value, length=50):
    """Truncate string with ellipsis"""
    if not value:
        return ''
    if len(value) <= length:
        return value
    return value[:length] + '...'

@contextfilter
def md5_hash(context, value):
    """Generate MD5 hash (for demonstration purposes)"""
    if not value:
        return ''
    return hashlib.md5(str(value).encode()).hexdigest()

@contextfilter
def request_id_filter(context, value=None):
    """Get request ID from context

    Used as "{{ request_id|request_id_filter }}", so Jinja passes the piped
    value in addition to the context -- without the second parameter every
    render of admin.html died with "takes 1 positional argument but 2 were
    given". The value itself is unused: the ID comes from the request context.
    """
    from utils.request_context import get_request_context
    ctx = get_request_context()
    if ctx and hasattr(ctx, 'request_id'):
        return ctx.request_id
    return 'N/A'

@contextfilter
def format_file_size(context, size_bytes):
    """Format file size in human-readable format"""
    if not size_bytes:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

@contextfilter
def role_badge(context, role):
    """Generate role badge HTML with HTML-escaped role value to prevent XSS.

    The role value originates from the database and must be treated as
    untrusted.  html.escape() is applied before embedding it in HTML, and the
    result is wrapped in jinja2.Markup so Jinja2 renders it without
    double-escaping.  The template must NOT apply the |safe filter to this
    filter's output — Markup already signals that the content is pre-escaped.
    """
    role_colors = {
        'admin': 'danger',
        'project_manager': 'primary',
        'team_member': 'secondary'
    }
    # Normalise: None becomes empty string; other non-strings are coerced
    role_str = '' if role is None else str(role)
    # color comes from a hardcoded allowlist dict — always a trusted constant
    color = role_colors.get(role_str, 'secondary')
    # html.escape() encodes <, >, &, " so the untrusted role value cannot
    # inject HTML tags or break out of the span's text content.
    return Markup(f'<span class="badge badge-{color}">{html.escape(role_str)}</span>')

