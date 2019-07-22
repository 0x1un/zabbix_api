import json
from exceptions import ZabbixTemplateError
from urllib import request
from urllib.request import urlopen


class ZabbixApi():

    def __init__(self, url=None, user=None, password=None, version=False):
        url = url or "http://localhost"
        user = user or "Admin"
        password = password or "zabbix"
        self.url = url + '/api_jsonrpc.php'
        self.auth = None
        self._login(user=user, password=password)

    def _login(self, user='', password=''):
        res_login_info = self.do_request('user.login', {
            'user': user,
            'password': password
        })
        if res_login_info:
            self.auth = json.loads(res_login_info)['result']
        else:
            print("登录zabbix失败")

    def templateID_by_name(self, op='', _filter='') -> dict:
        """
        @param op: 操作符
        @parma _filter: 需要寻找的模板名称
        该方法会返回一个dict, 模板名为key, 查找到的id为value
        如果不填写参数将会返回所有查找到的模板
        """
        op = op or 'template.get'
        flag = False
        ops = {'template.get': 'template.get', 'hostgroup.get': 'hostgroup.get'}
        if op not in ops:
            raise ZabbixTemplateError("%s 不是合法api操作" % op)
        _filter = _filter or []
        param = {'output': 'extend', 'filter': {'host': _filter}}
        if op == 'hostgroup.get':
            param['filter'] = {'name': _filter}
            flag = True
        res = self.do_request(ops[op], params=param)
        results = json.loads(res).get('result', None)
        if not results:
            return
        ids = {
            x.get('name', None): x.get('groupid', None) for x in results
        } if flag else {
            x.get('name', None): x.get('templateid', None) for x in results
        }

        return ids

    def hostid_get_by_name(self, hosts_name: list = []):
        """
        @param hosts_name: 接受一个列表, 列表中为要查询的主机名称
        该方法返回一个列表, 形如 [{'Zabbix Server': 123}, {'ArchLinux': 456}]
        the key is hostname, value is host id
        """
        if not hosts_name:
            raise ZabbixTemplateError("缺少相关参数")
        params = {
            "output": ["hostid", "host"],
        }
        res = self.do_request('host.get', params=params)
        res = json.loads(res) if res else None
        #  host_ids = [{x.get('host'): x.get('hostid')} for x in res.get('result')]
        host_ids = [x.get('hostid') for x in res.get('result')]
        return host_ids

    def config_export(self, ids: list = [], obj="", fmt='xml',
                      write_file=False) -> str:
        """
        @param ids: 接收一个列表, 并且列表中的id都为字符串
        @param fmt: 为将要导出的文件格式, json或者xml
        该方法默认会导出主机的配置, 如果没有指定obj
        注意, 如果ids中有多个需要导出的配置, 它将会把这个多个配置输出为一个整体
        """
        obj = obj or "hosts"
        param = {"options": {obj: ids}, "format": fmt}
        res = self.do_request('configuration.export', param)
        res = json.loads(res)
        if res.get('result') and write_file:
            with open('output.{}'.format(fmt), 'w') as fp:
                fp.write(res.get('result'))
            return
        return res.get('result', None)

    def template_mass_op(self,
                         option: str = '',
                         templates: tuple = (),
                         link_to: list = []):
        """
        @param option: 添加到groups / hosts
        @param templates: 接受一个列表, 其中为字典, 样式{"templateid": 10001}
        @param link_to: 绑定到groups / hosts, 它是个列表, 并且只能接收字符串
        """
        if not (option and templates and link_to):
            raise ZabbixTemplateError("缺少相关参数")
        template_id = self.templateID_by_name("template.get", templates)
        ids = [{
            "templateid": str(x)
        } for x in template_id.values() if template_id]
        if option.__eq__("groups"):
            link_to = self.templateID_by_name("hostgroup.get", link_to)
        elif option.__eq__("hosts"):
            link_to = self.hostid_get_by_name(link_to)
        options = {"groups": "groupid", "hosts": "hostid"}
        params = {"templates": ids, options[option]: link_to}
        res = self.do_request('template.massadd', params=params)
        return json.loads(res).get('result')

    def template_delete_by_name(self, name: list = []) -> dict:
        """
        @param name: 需要传入一个列表, 列表中放入要删除的模板名称
        该方法会返回一个字典
        """
        if not name:
            raise ZabbixTemplateError("缺少要查询模板的名称 {}".format(name))
        res = self.templateID_by_name(op='template.get', _filter=name)
        if not res:
            return
        ids = [value for value in res.values()]
        result = self.do_request('template.delete', ids)
        return json.loads(result)

    def template_create(self, template_name, group_id, host_s=[]):
        if not template_name or not group_id:
            raise ZabbixTemplateError("请填写模板名称与所属组的id")
        param = {
            "host": template_name,
            "groups": {
                "groupid": group_id
            },
            "hosts": host_s
        }
        res = self.do_request('template.create', param)
        res = json.loads(res)
        status = res.get('result', None)
        if not status:
            return status
        return status

    @property
    def version(self):
        res = self.do_request('apiinfo.version')
        if res:
            return json.loads(res)['result']
        return None

    def do_request(self, method, params=None):
        request_json = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': '1',
        }

        if self.auth and (method not in ('user.login', 'apiinfo.version')):
            request_json['auth'] = self.auth

        data = json.dumps(request_json)
        if not isinstance(data, bytes):
            data = data.encode('utf-8')

        req = request.Request(self.url, data=data)
        req.get_method = lambda: 'POST'
        req.add_header('Content-Type', 'application/json-rpc')

        try:
            result = urlopen(req)
            result = result.read().decode('utf-8')
            res_json = json.loads(result)
        except ValueError as e:
            print("无法解析json: %s" % e.message)

        res_str = json.dumps(res_json, indent=4, separators=(',', ': '))
        return res_str


if __name__ == '__main__':
    zapi = ZabbixApi('http://127.0.0.1', 'Admin', 'zabbix')
    #  res = zapi.templateID_by_name('template.get', ['Template OS Windows'])
    res = zapi.template_mass_op(
        option="hosts",
        templates=['Template OS Windows', 'Template OS Linux'],
        link_to=['Linux servers'])
    print(res)
    #  zapi.hostid_get_by_name(['Zabbix Server'])
