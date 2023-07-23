#!/usr/bin/env python3
from __future__ import print_function
from typing import Container
import bfrt_grpc.client as gc
from bfrt_grpc.client import KeyTuple as KT
from bfrt_grpc.client import DataTuple as DT

class tableGrpcConnector(object):
    def __init__(self, grpc_addr = "192.168.8.109:50052", client_id = 0, device_id = 0, pipe = -1) -> None:
        # Connect to BF Runtime Server              192.168.8.108:50052 10.112.91.158:50052
        self.interface = gc.ClientInterface(grpc_addr = "192.168.8.109:50052", client_id = 0, device_id = 0)
        print('Connected to BF Runtime Server')

        # Get the information about the running program on the bfrt server.
        self.bfrt_info = self.interface.bfrt_info_get()
        print('The target runs program ', self.bfrt_info.p4_name_get())

        # Establish that you are working with this program
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())

        ####### You can now use BFRT CLIENT #######
        pipe_id = 0xffff
        if pipe != -1:
            pipe_id = pipe
        self.target = gc.Target(device_id = device_id, pipe_id = pipe_id)

    def read_table(self, table_name):
        table = self.bfrt_info.table_dict[table_name]
        print("Reading table %s " % table_name)
        response = table.entry_get(self.target, None, {"from_hw":True})
        for data , key in response:
            print("--------------------------------------------------------------------")
            print("data:",data)
            print("--------------------------------------------------------------------")
            print("key:",key)
            print("--------------------------------------------------------------------")
            print("\n")

    def clear_table(self, table_name):
        print("Clearing table %s" % table_name)
        table = self.bfrt_info.table_dict[table_name]
        key_list = list()
        response = table.entry_get(self.target, None, {"from_hw":True})
        for date, key in response:
            key_list.append(key)
        table.entry_del(self.target, key_list)
        print("Cleared %d entries from table %s" % (len(key_list), table_name))

    def add_entry(self, table_name,key_tuples, data_tuples, action_name):
        '''
        @para key_tuple 
        @para data_tuple 
        @para action_name 'Egress.mod_bs'
            key_list.append(table.make_key([gc.KeyTuple(name = 'eg_intr_md.egress_port', value = 3)]))
            data_list.append(table.make_data([gc.DataTuple(name = 'dstaddr', val = 0x123456)],action_name = 'Egress.mod_bs'))
        '''
        table = self.bfrt_info.table_dict[table_name]
        print("Adding entry to table %s" % table_name)
        key_list = list()
        data_list = list()
        keyTuple_list = list()
        dataTuple_list = list()

        for key_tuple in key_tuples:
            keyTuple_list.append(gc.KeyTuple(name = key_tuple.name, value = key_tuple.value, mask = key_tuple.mask, prefix_len = key_tuple.prefix_len, low = key_tuple.low, high = key_tuple.high)) 
        keys = table.make_key(keyTuple_list)
        key_list.append(keys)

        for data_tuple in data_tuples:
            dataTuple_list.append(gc.DataTuple(name = data_tuple.name, val = data_tuple.val, float_val = data_tuple.float_val, str_val = data_tuple.str_val, int_arr_val = data_tuple.int_arr_val, bool_arr_val = data_tuple.bool_arr_val, bool_val = data_tuple.bool_val, container_arr_val = data_tuple.container_arr_val, str_arr_val = data_tuple.str_arr_val))
        datas = table.make_data(dataTuple_list,action_name)
        data_list.append(datas)

        table.entry_add(self.target, key_list, data_list)
        print("--------------------------------------------------------------------\n Added entry \n | key: %s , data: % s , action_name: %s | \n to table %s \n --------------------------------------------------------------------\n" % ([key_tuple.__str__() for key_tuple in key_tuples], [data_tuple.__str__() for data_tuple in data_tuples], action_name, table_name)) 

    def get_key_tuple_from_input(self, keys):
        print('input key: name=, value=, mask=, prefix_len=, low=, high=\n')
        key_kvs = keys.split(',')
        key_dic = dict()
        for key_kv in key_kvs:
            k,v = key_kv.split('=')
            if k != 'name':
                key_dic.update({k:int(v)})
            else:
                key_dic.update({k:v})

        key_tuple = KT(key_dic.get('name'),key_dic.get('value'),key_dic.get('mask'),key_dic.get('prefix_len'),key_dic.get('low'),key_dic.get('high'))
        return key_tuple

    def get_data_tuple_from_input(self, datas):
        print('input data: name, val=None, float_val=None, str_val=None, int_arr_val=None, bool_arr_val=None, bool_val=None, container_arr_val=None, str_arr_val=None\n')
        data_kvs = datas.split(',')
        data_dic = dict()
        for data_kv in data_kvs:
            k,v = data_kv.split('=')
            if k == 'name' or k == 'str_val':
                data_dic.update({k:v})
            elif k == 'val':
                data_dic.update({k:int(v)})
            elif k == 'float_val':
                data_dic.update({k:float(v)})
            elif k == 'int_arr_val':
                int_arr = list(v)[1:-1]
                for i in range(len(int_arr)):
                    if int_arr[i] == ',':
                        int_arr.pop(i)
                    else:
                        int_arr[i] = int(int_arr[i])
                data_dic.update({k:int_arr})
            elif k == 'bool_arr_val':
                bool_arr = list(v)[1:-1]
                for i in range(len(bool_arr)):
                    if bool_arr[i] == ',':
                        bool_arr.pop(i)
                    else:
                        bool_arr[i] = bool_arr[i] == 'True'
                data_dic.update({k:bool_arr})
            elif k == 'bool_val':
                data_dic.update({k:v == 'True'})
            elif k == 'str_arr_val':
                str_arr = list(v)[1:-1]
                for i in range(len(str_arr)):
                    if str_arr[i] == ',':
                        str_arr.pop(i)
                data_dic.update({k:str_arr})
            elif k == 'container_arr_val':
                container_arr = list(v)[1:-1]
                for i in range(len(container_arr)):
                    if container_arr[i] == ',':
                        container_arr.pop(i)
                    else:
                        container_arr[i] = Container(container_arr[i])
                data_dic.update({k:container_arr})

        data_tuple = DT(name=data_dic.get('name'),
                        val=data_dic.get('val'),
                        float_val=data_dic.get('float_val'),
                        str_val=data_dic.get('str_val'),
                        int_arr_val=data_dic.get('int_arr_val'),
                        bool_arr_val=data_dic.get('bool_arr_val'),
                        bool_val=data_dic.get('bool_val'),
                        container_arr_val=data_dic.get('container_arr_val'),
                        str_arr_val=data_dic.get('str_arr_val'))
        return data_tuple