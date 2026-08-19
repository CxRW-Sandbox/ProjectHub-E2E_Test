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
    """Generate role badge HTML with HTML-escaped role value to prevent XSS."""
    role_colors = {
        'admin': 'danger',
        'project_manager': 'primary',
        'team_member': 'secondary'
    }
    color = role_colors.get(role, 'secondary')
    # Use html.escape() to prevent stored XSS from untrusted role values stored in the DB.
    # Markup() wraps the result so Jinja2 treats it as already-safe HTML,
    # preserving the |safe usage in the template while encoding the role text.
    return Markup(f'<span class="badge badge-{html.escape(color)}">{html.escape(str(role))}</span>')

