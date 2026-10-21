#dEV zix official > telegram > @XiZYELFI
import socket, os, binascii, json, select, requests, threading, re, time, struct, urllib3, random, shutil
from datetime import datetime
from packet import *
V = 5

LOG_PATH = "/storage/emulated/0/Android/data/com.dts.freefireth/files/BackendJsonLog/"
CONFIG_PATH = "/storage/emulated/0/Android/data/com.dts.freefireth/files/localconfig.json"
K = bytearray([0] * 16)
V_IV = bytearray([0] * 16)
keys_loaded = False
last_modified = 0
token = ""

BUNDLE_MAP = {
    "1": 914000002,
    "2": 914000003,
    "3": 914038001,
    "4": 914039001,
    "5": 914042001,
    "6": 914044001,
    "7": 914047001,
    "8": 914047002,
    "9": 914048001,
    "10": 914050001,
    "11": 914051001,
}

def create_config():
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        config = {"resetGuest": True, "checkHacker": False, "gmsdkEnableDebugLog": True, "debugInfoOverride": True, "debugInfoDisplay": True, "showDebugLog": True, "debugHack": True, "enableBackendJsonLog": True}
        with open(CONFIG_PATH, "w") as f: json.dump(config, f, indent=2)
        return True
    except: return False

def extract_keys_from_log():
    global K, V_IV, keys_loaded, last_modified, token
    try:
        if not os.path.exists(LOG_PATH): return False
        files = [f for f in os.listdir(LOG_PATH) if f.startswith("BackendLog") and f.endswith(".log")]
        if not files: return False
        latest_file = max(files, key=lambda x: os.path.getmtime(os.path.join(LOG_PATH, x)))
        file_path = os.path.join(LOG_PATH, latest_file)
        current_mtime = os.path.getmtime(file_path)
        if current_mtime == last_modified: return False
        last_modified = current_mtime
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f: content = f.read()
        match = re.search(r'http:MajorLogin\s*(\{.*?\n\})', content, re.DOTALL)
        if not match:
            ak_match = re.search(r'"ak"\s*:\s*\[([^\]]+)\]', content)
            if ak_match:
                ak_str = ak_match.group(1); ak_list = [int(x.strip()) for x in ak_str.split(',')]
                aiv_match = re.search(r'"aiv"\s*:\s*\[([^\]]+)\]', content)
                if aiv_match:
                    aiv_str = aiv_match.group(1); aiv_list = [int(x.strip()) for x in aiv_str.split(',')]
                    if len(ak_list) == 16 and len(aiv_list) == 16:
                        K = bytearray(ak_list); V_IV = bytearray(aiv_list); keys_loaded = True
                        cleanup_files(); return True
            return False
        data = json.loads(match.group(1))
        if "ak" in data and "aiv" in data:
            new_k = data["ak"]; new_v = data["aiv"]
            if len(new_k) == 16 and len(new_v) == 16:
                K = bytearray(new_k); V_IV = bytearray(new_v); keys_loaded = True
                if "token" in data:
                    token = data["token"]
                cleanup_files(); return True
    except: pass
    return False

def cleanup_files():
    try:
        if os.path.exists(CONFIG_PATH): os.remove(CONFIG_PATH)
        if os.path.exists(LOG_PATH): shutil.rmtree(LOG_PATH)
    except: pass

def monitor_keys():
    while True:
        try: extract_keys_from_log(); time.sleep(3)
        except: time.sleep(3)

def decode_uid(encoded_uid):
    try:
        n = 0; shift = 0; hex_bytes = bytes.fromhex(encoded_uid)
        for b in hex_bytes:
            n |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return n
    except: return None

def extract_text_from_1200(hex_data):
    try:
        if not hex_data.startswith('1200'): return None
        data = hex_data[10:]
        from protobuf_decoder.protobuf_decoder import Parser
        parser = Parser(); parsed = parser.parse(data)
        def parse_protobuf_manual(parsed):
            result = {}
            for x in parsed:
                if x.field not in result: result[x.field] = []
                if x.wire_type in ["varint", "string", "bytes"]: result[x.field].append(x.data)
                elif x.wire_type == "length_delimited": result[x.field].append(parse_protobuf_manual(x.data.results))
            return {k: v[0] if len(v) == 1 else v for k, v in result.items()}
        decoded = parse_protobuf_manual(parsed)
        if decoded:
            if 4 in decoded and isinstance(decoded[4], str): return decoded[4]
            if 5 in decoded and isinstance(decoded[5], dict):
                if 4 in decoded[5] and isinstance(decoded[5][4], str): return decoded[5][4]
            if 5 in decoded and isinstance(decoded[5], list):
                for item in decoded[5]:
                    if isinstance(item, dict) and 4 in item:
                        if isinstance(item[4], str): return item[4]
        return None
    except: return None

def load_emotes():
    try:
        with open('emote.json', 'r') as f:
            data = json.load(f)
            return {str(item['Number']): item['Id'] for item in data}
    except:
        return {}

def format_id(n):
    s = str(n)
    return '🗿'.join(s[i:i+3] for i in range(0, len(s), 3))

class Px:
    def __init__(self):
        self.u = "bot"; self.p = "bot"; self.s5 = None; self.s12 = None
        self.server_remotes = {}; self.client_remote = None; self.running = True
        self.current_uid = None; self.current_uid_decoded = None
        self.squad_player_id = None; self.squad_code = None
        self.squad_owner_id = None
        self.packett = None; self.packett1 = None; self.team_remote = None
        self.emotes = load_emotes()
        self.token = ""
        self.current_cmd = None
        self.lag_running = False
        self.chat_code = None
        self.chat_owner_id = None
        self.bundle_map = BUNDLE_MAP

    def eV(self, val):
        res = bytearray()
        while val > 0x7F:
            res.append((val & 0x7F) | 0x80); val >>= 7
        res.append(val & 0x7F)
        return bytes(res)

    def eT(self, f_n, w_t): return self.eV((f_n << 3) | w_t)
    def e3(self, f_n, val): return self.eT(f_n, 0) + self.eV(val)
    def eS(self, f_n, val):
        enc = val.encode('utf-8')
        return self.eT(f_n, 2) + self.eV(len(enc)) + enc
    def eM(self, f_n, data): return self.eT(f_n, 2) + self.eV(len(data)) + data

    def e14_3(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.e3(1, data[1]))
        if 2 in data: buf.extend(self.e3(2, data[2]))
        return bytes(buf)

    def e9_14(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.e3(1, data[1]))
        if 2 in data: buf.extend(self.e3(2, data[2]))
        if 3 in data and isinstance(data[3], dict):
            sub = self.e14_3(data[3]); buf.extend(self.eM(3, sub))
        return bytes(buf)

    def e9_13(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.e3(1, data[1]))
        return bytes(buf)

    def eU(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.eS(1, data[1]))
        if 2 in data: buf.extend(self.e3(2, data[2]))
        if 4 in data: buf.extend(self.e3(4, data[4]))
        if 5 in data: buf.extend(self.e3(5, data[5]))
        if 8 in data: buf.extend(self.eS(8, data[8]))
        if 10 in data: buf.extend(self.e3(10, data[10]))
        if 11 in data: buf.extend(self.e3(11, data[11]))
        if 13 in data:
            s13 = self.e9_13(data[13]); buf.extend(self.eM(13, s13))
        if 14 in data:
            s14 = self.e9_14(data[14]); buf.extend(self.eM(14, s14))
        return bytes(buf)

    def eA(self, data):
        buf = bytearray()
        if 2 in data: buf.extend(self.e3(2, data[2]))
        if 3 in data: buf.extend(self.e3(3, data[3]))
        return bytes(buf)

    def eI(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.e3(1, data[1]))
        if 2 in data: buf.extend(self.e3(2, data[2]))
        if 4 in data: buf.extend(self.eS(4, data[4]))
        if 5 in data: buf.extend(self.e3(5, data[5]))
        if 7 in data: buf.extend(self.e3(7, data[7]))
        if 9 in data:
            u_d = self.eU(data[9]); buf.extend(self.eM(9, u_d))
        if 10 in data: buf.extend(self.eS(10, data[10]))
        if 13 in data:
            a_d = self.eA(data[13]); buf.extend(self.eM(13, a_d))
        return bytes(buf)

    def eO(self, data):
        buf = bytearray()
        if 1 in data: buf.extend(self.e3(1, data[1]))
        if 2 in data: buf.extend(self.e3(2, data[2]))
        if 4 in data: buf.extend(self.e3(4, data[4]))
        if 5 in data:
            i_d = self.eI(data[5]); buf.extend(self.eM(5, i_d))
        return bytes(buf)

    def pH(self, data):
        enc = self.eO(data)
        return binascii.hexlify(enc).decode('utf-8')

    def zP(self, st, pk):
        p_len = len(pk)//2
        l_h = hex(p_len).split('x')[-1]
        z = "0000" if len(l_h) == 2 else "000" if len(l_h) == 3 else "00" if len(l_h) == 4 else "0"
        return f"{st}{z}{l_h}{pk}"

    def dm(self, id_encoded):
        ep = f"080000001708{id_encoded}100820022a0b089f8d06109f8d0618c801"
        if self.s5:
            self.s5.send(bytes.fromhex(ep))

    def d1(self):
        ep = "0600000a8e0880e5a28937100620022a8115089ed4d09d3d10011a4b5b695d5b635d5b625d5b4646303030305d625b4646333330305d6f5b4646363630305d545b4646393930305d7e5b4646434330305d7a5b4646464630305d495b4646463530305d585b635d32024d4540c03e48c1c1dc027af801089ed4d09d3d10821218830120a9222ae6017b2264616d616765223a20313239363037352c2022646561746873223a20323137352c20227069636b5f757073223a2039303230322c20226865616473686f7473223a20323630352c2022726f61645f6b696c6c73223a2034352c2022746f7031305f74696d6573223a20302c2022746f705f6e5f74696d6573223a203537312c2022686967686573745f6b696c6c73223a2033362c2022737572766976616c5f74696d65223a203831393339342c20226865616473686f745f6b696c6c73223a20313332372c202264697374616e63655f74726176656c6c6564223a20363035353131357d82019e02089ed4d09d3d10d61a189c0220bd2b2a8c027b2264616d616765223a20323139383137312c2022646561746873223a20333133302c202272657669766573223a203731342c20227069636b5f757073223a203134373930342c20226865616473686f7473223a20343039372c20226b6e6f636b5f646f776e223a20343035392c2022726f61645f6b696c6c73223a2036352c2022746f7031305f74696d6573223a20302c2022746f705f6e5f74696d6573223a203836312c2022686967686573745f6b696c6c73223a2033302c2022737572766976616c5f74696d65223a20313432323738302c20226865616473686f745f6b696c6c73223a20313530302c202264697374616e63655f74726176656c6c6564223a20393838363337377d8a01a502089ed4d09d3d10e03f188f0820f980012a92027b2264616d616765223a20373231313131362c2022646561746873223a20373132312c202272657669766573223a20323231352c20227069636b5f757073223a203433333638352c20226865616473686f7473223a2031323639302c20226b6e6f636b5f646f776e223a2031353730332c2022726f61645f6b696c6c73223a203335372c2022746f7031305f74696d6573223a20302c2022746f705f6e5f74696d6573223a20323037302c2022686967686573745f6b696c6c73223a2033322c2022737572766976616c5f74696d65223a20333835333130362c20226865616473686f745f6b696c6c73223a20343731392c202264697374616e63655f74726176656c6c6564223a2032363733393337337d9a01b902089ed4d09d3d100120082aac027b2264616d616765223a20323038302c2022646561746873223a20312c20227069636b5f757073223a203130362c20226865616473686f7473223a2031302c20226869745f636f756e74223a2036392c2022726f61645f6b696c6c73223a20302c2022746f705f6e5f74696d6573223a20302c2022686967686573745f6b696c6c73223a20382c2022726174696e675f706f696e7473223a2031322e372c2022737572766976616c5f74696d65223a203232332c2022676f6c645f6d6564616c5f636e74223a20312c20226865616473686f745f6b696c6c73223a20342c202273696c7665725f6d6564616c5f636e74223a20302c202264697374616e63655f74726176656c6c6564223a20333539362c2022726174696e675f656e61626c65645f67616d6573223a20317da201d802089ed4d09d3d100220082acb027b2264616d616765223a20323734382c2022646561746873223a20322c202272657669766573223a20322c20227069636b5f757073223a203137372c20226865616473686f7473223a2031302c20226869745f636f756e74223a2037362c20226b6e6f636b5f646f776e223a20372c2022726f61645f6b696c6c73223a20302c2022746f705f6e5f74696d6573223a20302c2022686967686573745f6b696c6c73223a20342c2022726174696e675f706f696e7473223a2032312e312c2022737572766976616c5f74696d65223a203731332c2022676f6c645f6d6564616c5f636e74223a20312c20226865616473686f745f6b696c6c73223a20332c202273696c7665725f6d6564616c5f636e74223a20302c202264697374616e63655f74726176656c6c6564223a20383332342c2022726174696e675f656e61626c65645f67616d6573223a20327daa01f202089ed4d09d3d1059180320ca012ae2027b2264616d616765223a203130333530362c2022646561746873223a2038362c202272657669766573223a2034302c20227069636b5f757073223a20393437322c20226865616473686f7473223a203233372c20226869745f636f756e74223a20333135392c20226b6e6f636b5f646f776e223a203232312c2022726f61645f6b696c6c73223a20302c2022746f705f6e5f74696d6573223a2031362c2022686967686573745f6b696c6c73223a2031312c2022726174696e675f706f696e7473223a203636322e363030312c2022737572766976616c5f74696d65223a2034313636312c2022676f6c645f6d6564616c5f636e74223a20382c20226865616473686f745f6b696c6c73223a2037312c202273696c7665725f6d6564616c5f636e74223a2031332c202264697374616e63655f74726176656c6c6564223a203336313337322c2022726174696e675f656e61626c65645f67616d6573223a2038397db001c202b801831fc20100ca01f601089ed4d09d3d10012aeb017b2264616d616765223a203131362c2022646561746873223a20312c202272657669766573223a20302c20227069636b5f757073223a2033322c20226865616473686f7473223a20302c20226b6e6f636b5f646f776e223a20302c2022726f61645f6b696c6c73223a20302c2022746f7031305f74696d6573223a20302c2022746f705f6e5f74696d6573223a20302c2022686967686573745f6b696c6c73223a20302c2022737572766976616c5f74696d65223a203134322c20226865616473686f745f6b696c6c73223a20302c202264697374616e63655f74726176656c6c6564223a20333134357dd201f301089ed4d09d3d10012ae8017b2264616d616765223a20302c2022646561746873223a20312c202272657669766573223a20302c20227069636b5f757073223a2031362c20226865616473686f7473223a20302c20226b6e6f636b5f646f776e223a20302c2022726f61645f6b696c6c73223a20302c2022746f7031305f74696d6573223a20302c2022746f705f6e5f74696d6573223a20302c2022686967686573745f6b696c6c73223a20302c2022737572766976616c5f74696d65223a2037312c20226865616473686f745f6b696c6c73223a20302c202264697374616e63655f74726176656c6c6564223a20323230397dd801d4d8d0ad03e001b2dd8dae03ea01515b695d5b635d5b625d5b4646303030305d7a5b4646333330305d695b4646363630305d585b4646393930305d205b4646434330305d545b4646464630305d655b4646463530305d415b4646434330305d6df00101f801558002a299a8dd039802dec4dfd206d002c302d802ae01e00289a0f8b1039803c9b180da05c2030410011801ca03044f423534f8038cfd81c50b800401da04020802e204120888c4a9983d10081a0028cae30130e0a111e804d80a8a050a0888c4a9983d18012200"
        if self.s5:
            self.s5.send(bytes.fromhex(ep))

    def Send(self, id_decoded, msg):
        try:
            if not self.s12 or id_decoded is None: return
            t_id = id_decoded
            data = {
                1: t_id,
                2: 18,
                4: 2,
                5: {
                    1: 16436701726,
                    2: t_id,
                    3: 2,
                    4: msg,
                    5: 1784195688,
                    7: 2,
                    9: {
                        1: "[i][c][b][FF0000]b[FF3300]o[FF6600]T[FF9900]~[FFCC00]z[FFFF00]I[FFF500]X[c]",
                        2: 902000328,
                        3: 901037021,
                        4: 317,
                        5: 827001004,
                        8: "zIX",
                        10: 1,
                        11: 2011,
                        13: {
                            1: 2,
                            2: 1
                        },
                        14: {
                            1: 11017917409,
                            2: 8,
                            3: {
                                2: 21,
                                1: 10
                            }
                        }
                    },
                    10: "vn",
                    13: {
                        1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",
                        2: 1,
                        3: 1
                    },
                    14: {
                        1: {
                            1: 4,
                            2: 1,
                            3: 100,
                            4: 1,
                            5: 1784195688,
                            6: "AR"
                        }
                    },
                    16: 2077693422601349120
                }
            }
            enc = self.pH(data)
            if enc:
                packet = self.zP("1200", enc)
                self.s12.send(bytes.fromhex(packet))
        except: pass

    def is_game_server(self, port):
        return (39800 <= port <= 39899) or (39600 <= port <= 39699) or port == 500 or port == 40001

    def get_server_key(self, address, port): return f"{address}:{port}"

    def get_game_server(self):
        for key, sock in self.server_remotes.items():
            if '398' in key or '396' in key or ':500' in key or ':40001' in key:
                return sock
        return None

    def parse_0500(self, hex_data):
        try:
            if not hex_data.startswith('0500'): return None
            data = hex_data[10:]
            pos = data.find('08')
            if pos == -1: return None
            protobuf_data = data[pos:]
            from protobuf_decoder.protobuf_decoder import Parser
            parser = Parser(); parsed = parser.parse(protobuf_data)
            def parse_protobuf_manual(parsed):
                result = {}
                for x in parsed:
                    if x.field not in result: result[x.field] = []
                    if x.wire_type in ["varint", "string", "bytes"]: result[x.field].append(x.data)
                    elif x.wire_type == "length_delimited": result[x.field].append(parse_protobuf_manual(x.data.results))
                return {k: v[0] if len(v) == 1 else v for k, v in result.items()}
            decoded = parse_protobuf_manual(parsed)
            if decoded:
                player_id = None; code = None; owner_id = None; chat_code = None
                if 5 in decoded and isinstance(decoded[5], dict):
                    if 1 in decoded[5]:
                        player_id = decoded[5][1]
                        owner_id = decoded[5][1]
                    if 31 in decoded[5]: code = decoded[5][31]
                    if 17 in decoded[5]: chat_code = decoded[5][17]
                if not player_id and 5 in decoded and isinstance(decoded[5], dict):
                    if 6 in decoded[5] and isinstance(decoded[5][6], dict):
                        if 1 in decoded[5][6]: player_id = decoded[5][6][1]
                if 31 in decoded and not code: code = decoded[31]
                if 1 in decoded and not player_id: player_id = decoded[1]
                if player_id and code:
                    self.squad_owner_id = owner_id or player_id
                    if chat_code:
                        self.chat_code = chat_code
                        self.chat_owner_id = owner_id or player_id
                    return player_id, code
            return None
        except: return None

    def send_ghost(self, player_id, name, code):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            exit_packet = Exit(11037044965, key_bytes, iv_bytes)
            target_sock.send(exit_packet)
            time.sleep(0.1)
            clean_name = re.sub(r'[^\w\s]', '', name)
            ghost_packet = ghost(player_id, clean_name, code, key_bytes, iv_bytes)
            target_sock.send(ghost_packet)
        except: pass

    def send_squad_open(self, encoded_uid, squad_type):
        try:
            if not keys_loaded: return
            decoded = decode_uid(encoded_uid)
            if decoded is None: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            squad_packet = OpEnSq(key_bytes, iv_bytes)
            target_sock.send(squad_packet)
            time.sleep(0.5)
            change_packet = Sq_bot(squad_type, decoded, key_bytes, iv_bytes)
            target_sock.send(change_packet)
        except: pass

    def send_emote(self, player_ids, emote_number, owner_id):
        try:
            if not keys_loaded: return
            if str(emote_number) not in self.emotes: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            emote_id = int(self.emotes[str(emote_number)])
            for pid in player_ids:
                try:
                    p_id = int(pid)
                    packet = emote(emote_id, p_id, owner_id, key_bytes, iv_bytes)
                    target_sock.send(packet)
                    time.sleep(0.15)
                except: pass
        except: pass

    def send_skin(self, skin_num):
        try:
            if not keys_loaded: return
            if str(skin_num) not in self.bundle_map:
                return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            skin_id = self.bundle_map[str(skin_num)]
            skin_packet = skins(skin_id, key_bytes, iv_bytes)
            target_sock.send(skin_packet)
        except: pass

    def start_loop(self, seconds, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            start_time = time.time()
            while time.time() - start_time < seconds:
                packet = xStart(key_bytes, iv_bytes)
                target_sock.send(packet)
                time.sleep(0.3)
            self.Send(decoded_uid, f"[C][B][00FF00]Start done")
        except: pass

    def lag_loop(self, seconds, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            start_time = time.time()
            self.lag_running = True
            while time.time() - start_time < seconds and self.lag_running:
                packet = LaGx(key_bytes, iv_bytes)
                target_sock.send(packet)
                time.sleep(0.01)
            self.lag_running = False
            self.Send(decoded_uid, f"[C][B][00FF00]Lag done")
        except:
            self.lag_running = False

    def spam_loop(self, Uid, count, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            packet = spam_sqwad(Uid, key_bytes, iv_bytes)
            for _ in range(count):
                target_sock.send(packet)
            self.Send(decoded_uid, f"[C][B][00FF00]Spam {count} invites sent")
        except: pass

    def spam_homm(self, Uid, count, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            packet = spam_hom(Uid, key_bytes, iv_bytes)
            for _ in range(count):
                target_sock.send(packet)
            self.Send(decoded_uid, f"[C][B][00FF00]Spam {count} invites sent")
        except: pass

    def msg_loop(self, msg, seconds, decoded_uid):
        try:
            if not keys_loaded: return
            if not self.chat_code or not self.chat_owner_id:
                self.Send(decoded_uid, "[C][B][FF0000]No chat data found")
                return
            target_sock = self.get_game_server()
            if not target_sock:
                self.Send(decoded_uid, "[C][B][FF0000]No game server")
                return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            chat_packet = chat(self.chat_owner_id, self.chat_code, key_bytes, iv_bytes)
            target_sock.send(chat_packet)
            time.sleep(0.5)
            start_time = time.time()
            count = 0
            while time.time() - start_time < seconds:
                msg_packet = msg_in_team(self.current_uid_decoded, self.chat_owner_id, msg, key_bytes, iv_bytes)
                target_sock.send(msg_packet)
                count += 1
                time.sleep(0.8)
            self.Send(decoded_uid, f"[C][B][00FF00]Msg sent {count} times")
        except: pass

    def status(self, target_uid, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            status_packet = GeT_Status(target_uid, key_bytes, iv_bytes)
            target_sock.send(status_packet)
        except: pass

    def handle_status_response(self, hex_data, decoded_uid):
        try:
            if not hex_data.startswith('0f00'): return
            packet = hex_data[10:]
            decoded = json.loads(DeCode_PackEt(packet))
            target_id = None; status = None; last_login = None; leader_id = None; group_count = None; group_max = None
            try:
                player_data = decoded["5"]["data"]["1"]["data"]
                target_id = player_data["1"]["data"]; status = player_data["3"]["data"]; last_login = player_data["4"]["data"]
                if "8" in player_data: leader_id = player_data["8"]["data"]
                if "9" in player_data: group_count = player_data["9"]["data"]
                if "10" in player_data: group_max = player_data["10"]["data"]
            except: pass
            if target_id is None:
                try:
                    target_id = decoded["1"]["data"]; status = decoded["2"]["data"]; last_login = decoded["4"]["data"]
                except: pass
            if target_id is None:
                try:
                    target_id = decoded["5"]["1"]["1"]; status = decoded["5"]["1"]["3"]; last_login = decoded["5"]["1"]["4"]
                except: pass
            if target_id is None:
                try:
                    def find_values(obj):
                        ids = []; stats = []; logs = []; leads = []; counts = []; maxs = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if k == "data" and isinstance(v, dict):
                                    if "1" in v and "data" in v["1"]: ids.append(v["1"]["data"])
                                    if "3" in v and "data" in v["3"]: stats.append(v["3"]["data"])
                                    if "4" in v and "data" in v["4"]: logs.append(v["4"]["data"])
                                    if "8" in v and "data" in v["8"]: leads.append(v["8"]["data"])
                                    if "9" in v and "data" in v["9"]: counts.append(v["9"]["data"])
                                    if "10" in v and "data" in v["10"]: maxs.append(v["10"]["data"])
                                find_values(v)
                        elif isinstance(obj, list):
                            for item in obj: find_values(item)
                        return ids, stats, logs, leads, counts, maxs
                    ids, stats, logs, leads, counts, maxs = find_values(decoded)
                    if ids and stats: target_id = ids[0]; status = stats[0]
                    if logs: last_login = logs[0]
                    if leads: leader_id = leads[0]
                    if counts: group_count = counts[0]
                    if maxs: group_max = maxs[0]
                except: pass
            if target_id is None or status is None:
                self.Send(decoded_uid, "[b][c]No data found")
                return
            msgs = []
            t_id = format_id(target_id)
            if status == 1:
                msgs.append(f"[b][c]Status : Solo"); msgs.append(f"Uid : {t_id}")
            elif status == 2:
                msgs.append(f"[b][c]Status : In Squad"); msgs.append(f"Uid : {t_id}")
                if leader_id: msgs.append(f"Leader : {format_id(leader_id)}")
                if group_count is not None and group_max is not None: msgs.append(f"Count : {group_count}/{group_max+1}")
            elif status in [3, 5]:
                msgs.append(f"[b][c]Status : In Game"); msgs.append(f"Uid : {t_id}")
            else:
                msgs.append(f"[b][c]Status : {status}"); msgs.append(f"Uid : {t_id}")
            if last_login: msgs.append(f"Login : {datetime.fromtimestamp(last_login).strftime('%I:%M %p %d/%m/%y')}")
            for msg in msgs:
                self.Send(decoded_uid, msg)
                time.sleep(0.15)
        except: pass

    def getid(self, target_uid, decoded_uid):
        try:
            if not keys_loaded: return
            target_sock = self.get_game_server()
            if not target_sock: return
            key_bytes = bytes(K); iv_bytes = bytes(V_IV)
            status_packet = GeT_Status(target_uid, key_bytes, iv_bytes)
            target_sock.send(status_packet)
        except: pass

    def handle_getid_response(self, hex_data, decoded_uid):
        try:
            if not hex_data.startswith('0f00'): return
            packet = hex_data[10:]
            decoded = json.loads(DeCode_PackEt(packet))
            room_id = None
            try:
                player_data = decoded["5"]["data"]["1"]["data"]
                if "15" in player_data: room_id = player_data["15"]["data"]
            except: pass
            if room_id is None:
                try:
                    def find_room(obj):
                        rooms = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if k == "data" and isinstance(v, dict):
                                    if "15" in v and "data" in v["15"]: rooms.append(v["15"]["data"])
                                find_room(v)
                        elif isinstance(obj, list):
                            for item in obj: find_room(item)
                        return rooms
                    rooms = find_room(decoded)
                    if rooms: room_id = rooms[0]
                except: pass
            if room_id: self.Send(decoded_uid, f"{format_id(room_id)}")
            else: self.Send(decoded_uid, "Not in room")
        except: pass

    def hC(self, conn):
        try:
            ver, n_m = conn.recv(2)
        except: conn.close(); return
        mths = []
        for _ in range(n_m):
            try: mths.append(conn.recv(1)[0])
            except: break
        if 2 not in set(mths): conn.close(); return
        conn.sendall(bytes([V, 2]))
        try:
            ver = conn.recv(1)[0]; u_len = conn.recv(1)[0]
            usr = conn.recv(u_len).decode('utf-8')
            p_len = conn.recv(1)[0]; pwd = conn.recv(p_len).decode('utf-8')
            resp = bytes([ver, 0]); conn.sendall(resp)
        except: conn.close(); return
        try: ver, cmd, _, a_t = conn.recv(4)
        except: conn.close(); return
        if a_t == 1: addr = socket.inet_ntoa(conn.recv(4))
        elif a_t == 3:
            d_len = conn.recv(1)[0]; addr = conn.recv(d_len)
            try: addr = socket.gethostbyname(addr)
            except: addr = "127.0.0.1"
        else: conn.close(); return
        port = int.from_bytes(conn.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((addr, port))
                bind_address = remote.getsockname()
                server_key = self.get_server_key(addr, port)
                self.server_remotes[server_key] = remote
            else: conn.close(); return
            addr_bytes = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port_bytes = bind_address[1]
            reply = b''.join([V.to_bytes(1,'big'), int(0).to_bytes(1,'big'), int(0).to_bytes(1,'big'), int(1).to_bytes(1,'big'), addr_bytes.to_bytes(4,'big'), port_bytes.to_bytes(2,'big')])
        except:
            reply = b''.join([V.to_bytes(1,'big'), int(5).to_bytes(1,'big'), int(0).to_bytes(1,'big'), a_t.to_bytes(1,'big'), int(0).to_bytes(4,'big'), int(0).to_bytes(4,'big')])
        try: conn.sendall(reply)
        except: conn.close(); return
        if reply[1] == 0 and cmd == 1: self.eL(conn, remote, server_key)
        conn.close()

    def eL(self, cl, rem, server_key):
        self.client_remote = cl
        cl.settimeout(0.1); rem.settimeout(0.1)
        while self.running:
            try:
                rlist, _, _ = select.select([cl, rem], [], [], 0.1)
                if cl in rlist:
                    try:
                        dC = cl.recv(4096)
                        if not dC: break
                        if '0515' in dC.hex()[0:4] and len(dC.hex()) < 50:
                            self.packett1 = dC; self.team_remote = rem
                        if '0515' in dC.hex()[0:4] and len(dC.hex()) >= 141:
                            self.packett = dC; self.team_remote = rem
                        if rem.send(dC) <= 0: break
                    except: break
                if rem in rlist:
                    try:
                        dt = rem.recv(4096)
                        if not dt: break
                        packet_type = dt.hex()[:4] if len(dt.hex()) >= 4 else "unknown"
                        packet_len = len(dt.hex()) // 2
                        if '0500' in dt.hex()[:4]:
                            self.s5 = cl
                        if '1200' in dt.hex()[:4]:
                            self.s12 = cl
                        if '0500' in dt.hex()[:4] and packet_len >= 500:
                            parsed = self.parse_0500(dt.hex())
                            if parsed:
                                self.squad_player_id, self.squad_code = parsed
                        if '0f00' in dt.hex()[:4]:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            if self.current_cmd == 'status':
                                self.handle_status_response(dt.hex(), decoded)
                            elif self.current_cmd == 'getid':
                                self.handle_getid_response(dt.hex(), decoded)
                            self.current_cmd = None
                        if dt.hex().startswith("0500000") and packet_len >= 600:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            self.current_uid = uid_enc
                            self.current_uid_decoded = decoded
                            self.token = token
                            threading.Timer(0.3, self.Send, args=(decoded, """[i][b][c][FFFFFF] WLcomE To boT ~> dEV zIX 

[e6df22][B] Telegram Official : 
[FF69B4]@AKZAX ONTIBAN 

[e6df22][B] Instagram Official : 
[FF69B4]@--‐----

[9370DB]To See Command ?
[0dff9a]/help

[fffff4]ملاحظة : هاذا البوت يستخدم مع سيرفر العبه مثال انه يضهر كل شي عند الاعبين و حقيقي ليس بروكسي وهمي + استمتعوا

[0dfff7]ENJoY mY TcP ~ proxy ! .""")).start()
                            threading.Thread(target=self.d1).start()
                        if '1200' in dt.hex()[0:4] and b'/dm' in dt:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            threading.Timer(0.4, self.dm, args=(uid_enc,)).start()
                            threading.Timer(0.5, self.Send, args=(decoded, "[C][B][00FF00]DonE ~ dm")).start()
                        if '1200' in dt.hex()[0:4] and b'/sq3' in dt:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            threading.Timer(0.4, self.send_squad_open, args=(uid_enc, 3)).start()
                            threading.Timer(0.6, self.Send, args=(decoded, "[C][B][00FF00]Squad 3 Opened")).start()
                        if '1200' in dt.hex()[0:4] and b'/sq5' in dt:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            threading.Timer(0.4, self.send_squad_open, args=(uid_enc, 5)).start()
                            threading.Timer(0.6, self.Send, args=(decoded, "[C][B][00FF00]Squad 5 Opened")).start()
                        if '1200' in dt.hex()[0:4] and b'/sq6' in dt:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            threading.Timer(0.4, self.send_squad_open, args=(uid_enc, 6)).start()
                            threading.Timer(0.6, self.Send, args=(decoded, "[C][B][00FF00]Squad 6 Opened")).start()
                        if '1200' in dt.hex()[0:4] and b'/skin' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        skin_num = parts[1]
                                        if skin_num in self.bundle_map:
                                            threading.Timer(0.4, self.send_skin, args=(skin_num,)).start()
                                            threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Skin {skin_num} Sent")).start()
                                        else:
                                            threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Invalid skin number (1-11)")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /skin <1-11>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /skin <1-11>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/start' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        seconds = int(parts[1])
                                        threading.Timer(0.4, self.start_loop, args=(seconds, decoded)).start()
                                        threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Start {seconds}s")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /start <seconds>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /start <seconds>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/lag' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        seconds = int(parts[1])
                                        threading.Timer(0.4, self.lag_loop, args=(seconds, decoded)).start()
                                        threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Lag {seconds}s")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /lag <seconds>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /lag <seconds>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/spam' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 3:
                                        target_uid = parts[1]
                                        count = int(parts[2])
                                        threading.Timer(0.4, self.spam_loop, args=(target_uid, count, decoded)).start()
                                        threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Spam {count} invites")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /spam <id> <count>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /spam <id> <count>")).start()
                            except: pass
                            
                        if '1200' in dt.hex()[0:4] and b'/hom' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 3:
                                        target_uid = parts[1]
                                        count = int(parts[2])
                                        threading.Timer(0.4, self.spam_homm, args=(target_uid, count, decoded)).start()
                                        threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]txt {count} ")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /hom <id> 1")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /hom <id> 1")).start()
                            except: pass
                            
                            
                        if '1200' in dt.hex()[0:4] and b'/msg' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 3:
                                        msg = ' '.join(parts[1:-1])
                                        seconds = int(parts[-1])
                                        threading.Timer(0.4, self.msg_loop, args=(msg, seconds, decoded)).start()
                                        threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Msg started {seconds}s")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /msg <text> <seconds>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /msg <text> <seconds>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/status' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        target_uid = parts[1]
                                        self.current_cmd = 'status'
                                        threading.Timer(0.4, self.status, args=(target_uid, decoded)).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /status <id>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /status <id>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/getid' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        target_uid = parts[1]
                                        self.current_cmd = 'getid'
                                        threading.Timer(0.4, self.getid, args=(target_uid, decoded)).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /getid <id>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /getid <id>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/ghost' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 2:
                                        name = ' '.join(parts[1:])
                                        if self.squad_player_id and self.squad_code:
                                            threading.Timer(0.4, self.send_ghost, args=(self.squad_player_id, name, self.squad_code)).start()
                                            threading.Timer(0.7, self.Send, args=(decoded, f"[C][B][00FF00]Ghost {name} Sent")).start()
                                        else:
                                            threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]No Squad Data")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /ghost <name>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /ghost <name>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/emote' in dt:
                            try:
                                msg_text = extract_text_from_1200(dt.hex())
                                uid_enc = dt.hex()[12:22]
                                decoded = decode_uid(uid_enc)
                                if msg_text:
                                    parts = msg_text.strip().split()
                                    if len(parts) >= 3:
                                        emote_number = parts[-1]
                                        player_ids = parts[1:-1]
                                        if len(player_ids) >= 1 and len(player_ids) <= 4:
                                            if self.squad_owner_id:
                                                threading.Timer(0.4, self.send_emote, args=(player_ids, emote_number, self.squad_owner_id)).start()
                                                threading.Timer(0.6, self.Send, args=(decoded, f"[C][B][00FF00]Emote {emote_number} Sent To {len(player_ids)}")).start()
                                            else:
                                                threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]No Squad Owner")).start()
                                        else:
                                            threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /emote <id1~id4> <num>")).start()
                                    else:
                                        threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /emote <id1~id4> <num>")).start()
                                else:
                                    threading.Timer(0.3, self.Send, args=(decoded, "[C][B][FF0000]Usage: /emote <id1~id4> <num>")).start()
                            except: pass
                        if '1200' in dt.hex()[0:4] and b'/help' in dt:
                            uid_enc = dt.hex()[12:22]
                            decoded = decode_uid(uid_enc)
                            hlp = """[I][B][C]
[FFD700] تحويل الفريق إلى
[FF2A2A]/sq3 --> /sq5 --> /sq6

[FFD700]زيادة الجواهر و القولد
[FF2A2A]/dm

[FFD700] استدعاء شبح في الفريق
[FF2A2A]/ghost <name>

[FFD700] سبام طلبات فريق في حسابك
[FF2A2A]/spam <id> <count>

[FFD700] بعث رسالة لصاحبك الذي غير متصل
[FF2A2A]/hom <id> 1

[FFD700] تعليق الفريق
[FF2A2A]/lag <seconds>

[FFD700] استدعاء حالة الاعب
[FF2A2A]/status <id>

[FFD700] بدا الفريق إجباري
[FF2A2A]/start <seconds>

[FFD700] جلب ايدي الروم عبر ايدي الاعب
[FF2A2A]/getid <id>

[FFD700] ترقيص لاعبين في الفريق
[FF2A2A]/emote <id1~id4> < 1-->1000 >

[FFD700] تغيير السكن في الفريق
[FF2A2A]/skin <1-11>

[FFD700] ارسال رسائل في شات الفريق
[FF2A2A]/msg <text> <seconds>"""
                            threading.Timer(0.3, self.Send, args=(decoded, hlp)).start()
                        if cl.send(dt) <= 0: break
                    except socket.timeout: pass
                    except: break
            except: break
        try:
            cl.close(); rem.close()
            if server_key in self.server_remotes: del self.server_remotes[server_key]
        except: pass

    def rn(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port)); s.listen(5)
        while self.running:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self.hC, args=(conn,), daemon=True).start()
            except: pass
        s.close()

def st():
    create_config()
    threading.Thread(target=monitor_keys, daemon=True).start()
    px = Px(); px.rn('127.0.0.1', 3000)
print('StArT TcP ~ PrOXy ~> 127.0.0.1 -> 3000 -> bot -> bot ')
if __name__ == "__main__": st()