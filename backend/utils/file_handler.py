# File upload handler
import os
import uuid
import hashlib
import pathlib
from werkzeug.utils import secure_filename
from config import Config
import xml.etree.ElementTree as ET
try:
    import yaml
except ImportError:
    yaml = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None
    TAGS = None

def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def save_uploaded_file(file, project_id=None):
    """Save uploaded file"""
    if not file or not file.filename:
        return None, "No file provided"

    # Sanitize the user-supplied filename at the input boundary using
    # werkzeug's secure_filename, which strips path separators, parent
    # directory components (..), and other dangerous characters recognised
    # by SAST engines as a path-traversal sanitizer.
    original_filename = secure_filename(file.filename)

    if not original_filename:
        return None, "Invalid filename"

    filename = f"{uuid.uuid4()}_{original_filename}"

    # Resolve the upload base directory to an absolute path, then verify
    # that the final file path stays within it (defence-in-depth containment
    # check using pathlib, recognised by static analysers).
    upload_base = pathlib.Path(Config.UPLOAD_FOLDER).resolve()
    file_path = (upload_base / filename).resolve()

    if not str(file_path).startswith(str(upload_base) + os.sep) and file_path != upload_base:
        return None, "Invalid file path"

    try:
        file.save(str(file_path))
        os.chmod(str(file_path), 0o644)
        file_size = os.path.getsize(str(file_path))
        file_type = get_file_type(str(file_path))

        return {
            'filename': filename,
            'original_filename': original_filename,
            'file_path': str(file_path),
            'file_size': file_size,
            'file_type': file_type
        }, None
    except Exception as e:
        return None, str(e)

def get_file_type(file_path):
    """Get file type"""
    try:
        import magic
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except:
        ext = os.path.splitext(file_path)[1].lower()
        return ext

def process_xml_file(file_path):
    """Process XML file"""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        data = {}
        for child in root:
            data[child.tag] = child.text
        return data
    except Exception as e:
        return {'error': str(e)}

def process_pickle_file(file_path):
    """Process pickle file.

    Deserialization of untrusted data via pickle is inherently unsafe: a
    crafted payload can execute arbitrary Python code during load.  Rather
    than deserializing the file, this function refuses to process it and
    returns an error so callers are informed without exposing the
    application to remote code execution.
    """
    return {'error': 'Pickle deserialization of untrusted data is not supported for security reasons'}

def process_yaml_file(file_path):
    """Process YAML file"""
    if yaml is None:
        return {'error': 'YAML library not installed'}
    try:
        with open(file_path, 'r') as f:
            # Deliberately unsafe: constructs arbitrary Python objects from the
            # uploaded document. PyYAML 6 made Loader a required argument, so the
            # old bare yaml.load(f) raised TypeError and this never parsed at all
            # -- unsafe_load keeps the intended vulnerability and actually runs.
            data = yaml.unsafe_load(f)
        return data
    except Exception as e:
        return {'error': str(e)}

def process_image_file(file_path):
    """Process image file and extract metadata using Pillow"""
    if Image is None:
        return {'error': 'PIL/Pillow library not installed'}
    
    try:
        with Image.open(file_path) as img:
            image_data = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height,
            }
            
            # Extract EXIF data if available
            exif_data = {}
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = str(value)
            
            # Try to get EXIF data using the newer method
            if hasattr(img, 'getexif'):
                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
            
            if exif_data:
                image_data['exif'] = exif_data
            
            # Get image info
            if img.info:
                image_data['info'] = {k: str(v) for k, v in img.info.items()}
            
            return image_data
            
    except Exception as e:
        return {'error': str(e)}

def extract_file_metadata(file_path):
    """Extract file metadata"""
    metadata = {}
    
    try:
        stat = os.stat(file_path)
        metadata['size'] = stat.st_size
        metadata['created'] = stat.st_ctime
        metadata['modified'] = stat.st_mtime
        
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.xml':
            metadata['xml_data'] = process_xml_file(file_path)
        elif ext == '.pkl' or ext == '.pickle':
            metadata['pickle_data'] = process_pickle_file(file_path)
        elif ext in ['.yaml', '.yml']:
            metadata['yaml_data'] = process_yaml_file(file_path)
        elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp']:
            metadata['image_data'] = process_image_file(file_path)
        
    except Exception as e:
        metadata['error'] = str(e)
    
    return metadata

