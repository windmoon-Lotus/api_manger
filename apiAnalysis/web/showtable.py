import json
import os
import re
import uuid
from threading import Thread
from apiAnalysis.main import main
from apiAnalysis import init
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_paginate import Pagination, get_page_args
from apiAnalysis.db.collection import *
from apiAnalysis.common.decorators import *
from apiAnalysis.conf.conf import logger

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# MongoDB 连接配置
connect(db='apihandl', host='mongodb://localhost:27017')
app = Flask(__name__, template_folder='../templates')
app.config['UPLOAD_FOLDER'] = 'uploads/'

def get_documents(collection_class, filter_name=None, sort_field='', sort_direction=-1):
    # 筛选逻辑
    query = collection_class.objects
    if filter_name:
        query = query.filter(name__icontains=filter_name)

    # 排序逻辑
    if sort_direction == 'asc':
        query = query.order_by(f'+{sort_field}')
    else:
        query = query.order_by(f'-{sort_field}')
    return query


@app.route('/')
@templated("/index.html")
def index():
    # 获取分页参数
    page, per_page, offset = get_page_args(
        page_parameter='page', per_page_parameter='per_page'
    )

    # 获取筛选和排序参数
    filter_name = request.args.get('filter_name', '')
    sort_field = request.args.get('sort_field', 'parameterid')
    sort_direction = request.args.get('sort_direction', 'desc')

    # 查询数据（默认使用 User 集合）
    collection_class = parameter_data  # 可以动态切换为 Product 或其他集合
    documents = get_documents(collection_class, filter_name, sort_field, sort_direction)
    total = documents.count()
    pagination_documents = documents.skip(offset).limit(per_page)
    # 分页控件
    pagination = Pagination(
        page=page, per_page=per_page, total=total,
        css_framework='bootstrap4'
    )

    # 获取字段白名单
    editable_fields = collection_class.get_editable_fields()
    return render_template(
        'index.html',
        documents=pagination_documents,
        pagination=pagination,
        filter_name=filter_name,
        sort_field=sort_field,
        sort_direction=sort_direction,
        editable_fields=editable_fields,
        collection_name=collection_class.__name__
    )


@app.route('/add/parameter_data', methods=['POST'])
def add():
    collection_class = parameter_data  # 可以动态切换为 Product 或其他集合
    data = {field: request.form[field] for field in collection_class.get_editable_fields()}
    collection_class(**data).save()
    return redirect(url_for('index'))


@app.route('/edit/<id>', methods=['POST'])
def edit(id):
    collection_class = parameter_data  # 可以动态切换为 Product 或其他集合
    data = request.get_json()
    document = collection_class.objects.get(id=id)
    for field in collection_class.get_editable_fields():
        logger.debug("edit field=%s value_type=%s", field, type(document[field]))
        if data[field] == "[]":
            data[field] = []
        elif "List" in str(type(document[field])):
            valid_json_str = re.sub(r"(?<!\\)'", '"', data[field])
            #print(type(json.dumps(data[field])))
            data[field] = json.loads(valid_json_str)
        else:
            pass
        setattr(document, field, data[field])
    document.save()
    return '', 204  # 返回空响应，表示成功

@app.route('/delete/<id>')
def delete(id):
    collection_class = parameter_data  # 可以动态切换为 Product 或其他集合
    collection_class.objects.get(id=id).delete()
    return redirect(url_for('index'))




# 存储任务状态和结果（生产环境建议用数据库）
tasks = {}

# 确保上传文件夹存在
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# 定义内部处理方法
def process_file(file_path, method, params):
    """模拟长时间执行的任务"""
    if method == "method1":
        return f"Processed by method1 with params: {params}"
    elif method == "method2":
        return f"Processed by method2 with params: {params}"
    else:
        return "Unknown method"


def async_task(task_id, file_path, method, params):
    """后台执行任务并更新状态"""

    tasks[task_id] = {"status": "running", "result": None}
    try:
        if method == "method1":
            args = "-i" + file_path + params
            main(args)
        #result = process_file(file_path, method, params)
        tasks[task_id] = {"status": "completed"}
    except Exception as e:
        tasks[task_id] = {"status": "failed", "result": str(e)}


@app.route('/op_flow', methods=['GET', 'POST'])
def op_flow():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # 获取参数
            method = request.form.get('method')
            params = request.form.get('params', '')

            # 生成唯一任务ID
            task_id = str(uuid.uuid4())

            # 启动后台线程执行任务
            thread = Thread(target=async_task, args=(task_id, file_path, method, params))
            thread.start()

            # 返回任务ID供前端查询状态
            return jsonify({"task_id": task_id})

    return render_template('op_flow.html')


@app.route('/task/<task_id>')
def get_task_status(task_id):
    """查询任务状态"""
    task = tasks.get(task_id, {"status": "unknown"})
    return jsonify(task)



if __name__ == '__main__':
    '''
    init()
    args = ["-i", "test_flows", "-p"]
    main(args)
    '''
    app.run(debug=True)
