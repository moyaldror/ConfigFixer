import os
import shutil
import uuid

from flask import Flask, render_template, request, make_response
from werkzeug import secure_filename
from werkzeug.debug import get_current_traceback

from fixer_helpers import get_config_parser

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DOWNLOADS'] = 'downloads'
app.config['ROOT_DIR'] = os.getcwd()

try:
    shutil.rmtree(os.path.abspath(app.config['UPLOAD_FOLDER']))
    shutil.rmtree(os.path.abspath(app.config['DOWNLOADS']))
except:
    pass

os.mkdir(app.config['UPLOAD_FOLDER'])
os.mkdir(app.config['DOWNLOADS'])


def create_workdir(uid):
    # os.chdir(os.path.abspath(app.config['ROOT_DIR']))
    workdir = os.path.join(app.config['UPLOAD_FOLDER'], uid)
    os.mkdir(workdir)

    return workdir


def generate_file_response(workdir, filename):
    # os.chdir(os.path.abspath(app.config['ROOT_DIR']))
    res_file = os.path.join(workdir, filename)
    with open(res_file, 'rb') as f:
        yield from f

    os.unlink(res_file)


def get_res(config_file, sessid):
    get_config_parser(config_file=config_file)(config_file=config_file,
                                               out_dir=app.config['DOWNLOADS'],
                                               out_file_name=sessid)
    resfile = '%s.tar.gz' % sessid
    r = app.response_class(generate_file_response(workdir=app.config['DOWNLOADS'], filename=resfile))
    r.headers.set('Content-Disposition', 'attachment', filename=resfile)
    return r, resfile


@app.errorhandler(Exception)
def exception_handler(error):
    return get_current_traceback(skip=1, show_hidden_frames=True,
                                 ignore_system_exceptions=False).render_full(evalex=True)


@app.route('/')
def index():
    resp = make_response(render_template('./index.html'))
    resp.set_cookie(key='sessid', value=uuid.uuid4().hex)
    return resp


@app.route('/text_config', methods=['POST'])
def get_text_config():
    sessid = request.cookies.get('sessid')
    upload_dir = create_workdir(uid=sessid)
    tmp_config_file = os.path.join(upload_dir, 'config.txt')

    with open(tmp_config_file, 'w') as cfg:
        cfg.write(request.form['textConfig'].replace('\r\n', '\n'))

    try:
        res, resfile = get_res(config_file=tmp_config_file, sessid=sessid)
    except Exception as e:
        print(e)
        raise e
        #res = make_response(render_template('./parserErr.html'))
    finally:
        os.chdir(os.path.abspath(app.config['ROOT_DIR']))
        shutil.rmtree(os.path.abspath(upload_dir))
        try:
            shutil.rmtree(os.path.abspath(os.path.join(app.config['DOWNLOADS']), sessid))
            os.unlink(os.path.abspath(os.path.join(app.config['DOWNLOADS']), resfile))
        except:
            pass

    return res


@app.route('/file_config', methods=['POST'])
def upload_file():
    sessid = request.cookies.get('sessid')
    f = request.files['file']
    filename = secure_filename(f.filename)
    work_dir = create_workdir(uid=sessid)
    file_location = os.path.join(work_dir, filename)
    f.save(file_location)

    try:
        res, resfile = get_res(config_file=file_location, sessid=sessid)
    except Exception as e:
        print(e)
        raise e
        # res = make_response(render_template('./parserErr.html'))
    finally:
        os.chdir(os.path.abspath(app.config['ROOT_DIR']))
        shutil.rmtree(os.path.abspath(work_dir))
        try:
            shutil.rmtree(os.path.abspath(os.path.join(app.config['DOWNLOADS']), sessid))
            os.unlink(os.path.abspath(os.path.join(app.config['DOWNLOADS']), resfile))
        except:
            pass

    return res

    # r = app.response_class(generate_file_response(workdir=work_dir, filename=filename))
    # r.headers.set('Content-Disposition', 'attachment', filename=filename)
    # return r


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)
