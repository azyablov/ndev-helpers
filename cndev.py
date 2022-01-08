#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
import textfsm
import jinja2
import logging
from pprint import pprint
from typing import Union, Dict, List, AnyStr
import functools
import time
from lxml import etree
import re
import inspect
import ncclient

# ==== Resource variables and matching patterns ====

ALERT = "Alert!"
NO_ALERT = "------"
NOKIA_NSMAP = {
    'None': 'urn:nokia.com:sros:ns:yang:sr:state',
    'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0',
    'nokia-conf': 'urn:nokia.com:sros:ns:yang:sr:conf',
    'nokia-state': 'urn:nokia.com:sros:ns:yang:sr:state',
    'state': 'urn:nokia.com:sros:ns:yang:sr:state'
}


# Decorators
def runtimeit_logger(logger: logging.Logger):
    def runtimeit(run_func):
        # Function to measure runtime
        @functools.wraps(run_func)
        def timeit(*args, **kwargs):
            start = time.time()
            # Run target function
            run_func_result = run_func(*args, **kwargs)
            end = time.time()
            logger.info(f"Runtime of {run_func.__name__}: {end - start} seconds")
            return run_func_result
        return timeit
    return runtimeit

# JSON helpers
def load_json_data(file_name: str) -> Dict:
    """
    The function facilitates parameters load from JSON file
    :param file_name:
    :return: dictionary
    """
    # Reading JSON file
    path_input_file: Union[bytes, str] = os.path.abspath(file_name)
    if os.path.exists(path_input_file) and os.access(path_input_file, os.R_OK):
        with open(path_input_file, mode='r', encoding='utf-8') as input_config_file:
            try:
                data = json.load(input_config_file)
            except json.JSONDecodeError as de:
                print(f'JSON format decode error.'
                      f'{de}')
                raise
        return data
    else:
        print("Can't access file {}".format(file_name))
        msg = "Please provide valid file name and/or path."
        raise ValueError(msg)

# TEXTFSM helpers
def apply_template(template: str, cli_output: str, debug: bool = False) -> Union[list, None]:
    path_to_template_file = os.path.abspath(template)
    if os.path.exists(path_to_template_file) and os.access(path_to_template_file, os.R_OK):
        with open(path_to_template_file, mode='r', encoding='utf-8') as tfh:
            re_table = textfsm.TextFSM(tfh)
            cli_data = re_table.ParseText(cli_output)
            if debug:
                print(cli_data)
            return cli_data
    else:
        msg = f"Incorrect template file name: {path_to_template_file}"
        raise ValueError(msg)
    return None

# Jinja helpers
def load_j2_env(path_to_templ: str = './j2') -> jinja2.Environment:
    """
    The function is loading j2 env
    :type path_to_templ: str
    :param path_to_templ: directory with j2 templates
    :return: j2 environment
    """
    if os.path.exists(path_to_templ) and os.access(path_to_templ, os.R_OK):
        temp_env = jinja2.Environment(loader=jinja2.FileSystemLoader(path_to_templ, followlinks=True),
                                      undefined=jinja2.StrictUndefined)
        return temp_env

# Logging
def enable_logging(name: str, log_file: str, level=logging.WARNING) -> logging.Logger:
    log_fmt = "[{asctime} {levelname:<8} [{name}:{filename:<10}:{lineno}] {message}"
    date_fmt = "%d/%m/%Y %H:%M:%S"
    log: logging.Logger = logging.getLogger(name)
    log.setLevel(level)
    formatter = logging.Formatter(fmt=log_fmt, datefmt=date_fmt, style='{')
    fh = logging.FileHandler(filename=log_file, encoding='utf-8')
    fh.setLevel(level=level)
    fh.setFormatter(formatter)
    log.addHandler(fh)
    return log

# XML helpers
def xml_to_tree(x: etree._Element, lvl: int = 1, preserve_ns: bool = False, text_strip: bool = True):
    # print(inspect.currentframe().f_code.co_name)
    if preserve_ns:
        tag = x.tag
    else:
        tag = re.sub(r'\{.*\}(.*)', r'\1', x.tag)
    if text_strip and x.text:
        text = x.text.strip()
    else:
        text = x.text if x.text else ""

    yield f"{'  ' * (lvl - 1)}|--Tag: {tag:<}" \
          f"{'  ' * (lvl - 1)}|  Text: {text:<}"

    for ch in x.getchildren():
        yield from xml_to_tree(ch, lvl + 1, preserve_ns, text_strip)


def get_path_to_root(e: etree._Element, preserve_ns: bool = False) -> List[AnyStr]:
    anc = e.getparent()
    path = []
    while anc is not None:
        path.insert(0,
                    anc.tag.strip() if preserve_ns
                    else re.sub(r'\{.*\}(.*)', r'\1', anc.tag.strip()))
        anc = anc.getparent()
    return path

def get_xml_str(e: etree._Element, pprn: bool = False) -> str:
    rstr = etree.tostring(e).decode()
    if pprn:
        pprint(rstr)
    return rstr

def load_xml_filter(fname, fdir: str = "sros_nf_filters") -> str:
    path_input_file: Union[bytes, str] = os.path.abspath(f"{fdir}/{fname}.xml")
    if os.path.exists(path_input_file) and os.access(path_input_file, os.R_OK):
        with open(path_input_file, mode='r', encoding='utf-8') as fh:
            print("fh type: ", end='')
            print(type(fh))
            data = fh.read()
        return data
    else:
        print("Can't load filter {}".format(fname))
        msg = f"Please directory {fdir} exist and intended filter present in the directory."
        raise ValueError(msg)


def get_sros_elem_config(nfd: ncclient.manager.Manager, xml_filter: str = "", source: str = "running", remove_blank_text: bool = False,
                         pprn: bool = False) -> etree._Element:
    """
    :param remove_blank_text: the same as etree.XMLParser remove_blank_text
    :param nfd: device manager
    :param xml_filter: subtree filter, see RFC4741, sec. #6
    :param source: source datastore
    :param pprn: pretty print received raw data, should be activated to preform debug
    """
    def_xml_filter = """
              <configure xmlns="urn:nokia.com:sros:ns:yang:sr:conf">
              </configure>"""
    if xml_filter:
        response_xml = nfd.get_config(source=source, filter=('subtree', xml_filter))
    else:
        response_xml = nfd.get_config(source=source, filter=('subtree', def_xml_filter))
    # Optionally print config
    if pprn:
        title = " Retrieved SROS XML config "
        print(20 * "=" + title + 20 * "=")
        print(response_xml.data_xml)
        print(40 * "=" + len(title))
    # Parse config from the string
    xml_par = etree.XMLParser(ns_clean=True, recover=True, encoding='utf-8', remove_blank_text=remove_blank_text)
    return etree.fromstring(text=response_xml.data_xml.encode('utf-8'), parser=xml_par)