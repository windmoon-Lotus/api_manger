import pywebio.session
from flask import app, Flask
from pywebio import start_server
from pywebio.output import *
from pywebio.input import *
from pywebio.pin import pin
from pywebio.platform.flask import webio_view
from pywebio.session import *
from db.collection import *
from mongoengine import connect, Document, StringField, IntField
import csv
import logging

#from tool.tool import load_data_from_mongodb
logger = logging.getLogger(__name__)

disconnect()
# MongoEngine 连接
connect("apihandle", host="mongodb://localhost:27017/")  # 替换为你的 MongoDB 连接字符串


# 定义 MongoEngine 模型

def handle_pagination(action, data_source, session_page, total_pages):
    if action == 'prev' and session_page > 1:
        session_page -= 1
    elif action == 'next' and session_page < total_pages:
        session_page += 1
    elif action == 'goto':
        new_page = input("输入页码", type=NUMBER, min=1, max=total_pages)
        session_page = new_page
    update_table(data_source, session_page)


def pywebio_app():
    # 设置页面环境
    set_env(title="MongoDB 分页显示", output_animation=False)
    put_markdown("## parameterData 数据")
    # 初始化分页
    update_table("parameterData", page=1)


def update_table(data_source="parameterData", page=1):
    session_page = page
    page_size = 50
    # 从 MongoDB 中加载初始数据
    # 加载数据和分页信息
    data = load_data_from_mongodb(data_source, session_page, page_size)

    total = get_total_count(data_source)
    total_pages = (total + page_size - 1) // page_size
    logger.debug("total_pages=%s", total_pages)
    # 清空旧内容
    clear("table_section")
    clear("pagination_section")
    # 渲染表格
    with use_scope("table_section"):
        if not data:
            put_text("暂无数据")
        else:
            columns = list(data[0].keys())
            table = put_datatable(
                data,
                column_order=columns,
                actions=[
                    ("Edit", lambda row_id: edit_row(data_source, row_id, data)),
                    ("Delete", lambda row_id: delete_row(data_source, row_id, data)),
                ],
                instance_id="id"
            )

            put_buttons([
                {'label': '上一页', 'value': 'prev'},
                {'label': '下一页', 'value': 'next'},
                {'label': f'当前页: {session_page}', 'value': 'current'},
                {'label': '跳转到', 'value': 'goto'}
            ], onclick=[
                lambda: handle_pagination('prev', data_source, session_page, total_pages),
                lambda: handle_pagination('next', data_source, session_page, total_pages),
                None,
                lambda: handle_pagination('goto', data_source, session_page, total_pages)
            ])


# 从 MongoDB 中加载数据
def load_data_from_mongodb(collection_name, page=1, page_size=50):
    conn = get_connection()
    collection = conn["apihandle"][collection_name]  # 获取集合
    skip = (page - 1) * page_size
    data = list(collection.find().skip(skip).limit(page_size))
    #data = list(collection.find({}, {"_id": 0}))
    for item in data:
        item["_id"] = str(item["_id"])
    return data


def get_total_count(collection_name):
    conn = get_connection()
    collection = conn["apihandle"][collection_name]
    return collection.count_documents({})


# 编辑行
def edit_row(data_source, row_id, column_id, data):
    row = data[row_id]
    new_data = input()
    logger.debug("edit_row new_data keys=%s", list(new_data.keys()) if isinstance(new_data, dict) else type(new_data))
    # 更新数据
    logger.debug("edit_row row_id=%s column_id=%s", row_id, column_id)
    logger.debug("edit_row row_snapshot=%s", row)
    #data[row_id].update(new_data)
    #sync_to_mongodb(data_source, data[row_id])  # 同步到 MongoDB
    toast("行已更新！", color="success")


# 插入行
def insert_row(data_source, row_id, data, table):
    new_row = {
        "id": len(data) + 1,  # 自动生成 ID
        "name": "New User",
        "email": "new@example.com",
        "role": "User",
    }
    data.insert(row_id + 1, new_row)  # 在选中行的下方插入
    sync_to_mongodb(data_source, new_row)  # 同步到 MongoDB
    toast("新行已插入！", color="success")
    table.update(data)  # 动态刷新表格


# 删除行
def delete_row(data_source, row_id, data):
    if data[row_id]["role"] == "Admin":
        toast("Admin 不允许删除！", color="error")
        return

    deleted_row = data.pop(row_id)
    delete_from_mongodb(data_source, deleted_row)  # 从 MongoDB 中删除
    toast("行已删除！", color="success")


# 导出 CSV
def export_csv(data):
    if not data:
        toast("没有数据可导出！", color="warning")
        return

    # 生成 CSV 文件
    csv_data = [list(data[0].keys())]  # 表头
    for row in data:
        csv_data.append(list(row.values()))

    # 保存为 CSV 文件
    with open("export.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(csv_data)

    toast("数据已导出为 export.csv！", color="success")


# 批量编辑
def batch_edit(data, table):
    selected_rows = pin.selected_rows  # 假设通过 pin 获取选中的行
    if not selected_rows:
        toast("请先选择要编辑的行！", color="warning")
        return

    new_data = input_group("批量编辑", [
        input("Name", name="name"),
        input("Email", name="email"),
        input("Role", name="role"),
    ])

    for row_id in selected_rows:
        data[row_id].update(new_data)
        sync_to_mongodb(data[row_id])  # 同步到 MongoDB

    toast("批量编辑完成！", color="success")
    table.update(data)


# 同步到 MongoDB
def sync_to_mongodb(data_source, row):
    try:
        # 如果行已存在，则更新；否则插入
        user = data_source.objects(id=row["id"]).first()
        if user:
            user.update(**row)
        else:
            data_source(**row).save()
    except Exception as e:
        toast(f"同步到 MongoDB 失败: {str(e)}", color="error")


# 从 MongoDB 中删除
def delete_from_mongodb(data_source, row):
    try:
        data_source.objects(id=row["id"]).delete()
    except Exception as e:
        toast(f"从 MongoDB 中删除失败: {str(e)}", color="error")


app = Flask(__name__)


@app.route('/example')
def example():
    update_table()


if __name__ == '__main__':
    start_server(pywebio_app, port=8888)
