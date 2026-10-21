import requests, json, binascii, time, urllib3, base64, datetime, re, socket, threading, random, os; from protobuf_decoder.protobuf_decoder import Parser; from Crypto.Cipher import AES; from Crypto.Util.Padding import pad, unpad; from datetime import datetime; from google.protobuf.timestamp_pb2 import Timestamp
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
Iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def xO(n):
    return 'َ'.join(str(n)[i:i+3] for i in range(0, len(str(n)), 3))

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def aZ(hx):
    cipher = AES.new(Key, AES.MODE_CBC, Iv)
    return cipher.encrypt(pad(bytes.fromhex(hx), AES.block_size)).hex()

def zA(hx):
    cipher = AES.new(Key, AES.MODE_CBC, Iv)
    return unpad(cipher.decrypt(bytes.fromhex(hx)), AES.block_size).hex()

def bZ(hx, k, v):
    return AES.new(k, AES.MODE_CBC, v).encrypt(pad(bytes.fromhex(hx), 16)).hex()

def zB(hx, k, v):
    return unpad(AES.new(k, AES.MODE_CBC, v).decrypt(bytes.fromhex(hx)), 16).hex()

def cZ(h, tp):
    e, h = [], int(h)
    while h:
        e.append((h & 0x7F) | (0x80 if h > 0x7F else 0))
        h >>= 7
    return bytes(e).hex() if tp == 'Uid' else None

def h(data):
    return gZ(data).hex()

def dZ(n):
    if n < 0: return ''
    h = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        h.append(b)
        if not n:
            break
    return bytes(h)

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = Fix_PackEt(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def zC(h):
    n = s = 0
    for b in bytes.fromhex(h):
        n |= (b & 0x7F) << s
        if not b & 0x80:
            break
        s += 7
    return n

def eZ(field_number, value):
    field_header = (field_number << 3) | 0
    return dZ(field_header) + dZ(value)

def fZ(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return dZ(field_header) + dZ(len(encoded_value)) + encoded_value

def gZ(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = gZ(value)
            packet.extend(fZ(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(eZ(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(fZ(field, value))
    return packet

def hZ(h):
    r = hex(h)
    f = str(r)[2:]
    if len(f) == 1:
        f = "0" + f
        return f
    return f

def color():
    color_list = [
        "[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]", 
        "[0000FF][b][c]", "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]",
        "[DCE775][b][c]", "[A8E6CF][b][c]", "[7CB342][b][c]", "[FF0000][b][c]",
        "[FFB300][b][c]", "[90EE90][b][c]", "[FF4500][b][c]", "[FFD700][b][c]",
        "[32CD32][b][c]", "[87CEEB][b][c]", "[9370DB][b][c]", "[FF69B4][b][c]",
        "[8A2BE2][b][c]", "[00BFFF][b][c]", "[1E90FF][b][c]", "[20B2AA][b][c]",
        "[00FA9A][b][c]", "[008000][b][c]", "[FFFF00][b][c]", "[FF8C00][b][c]",
        "[DC143C][b][c]", "[FF6347][b][c]", "[FFA07A][b][c]", "[FFDAB9][b][c]",
        "[CD853F][b][c]", "[D2691E][b][c]", "[BC8F8F][b][c]", "[F0E68C][b][c]",
        "[556B2F][b][c]", "[808000][b][c]", "[4682B4][b][c]", "[6A5ACD][b][c]",
        "[7B68EE][b][c]", "[8B4513][b][c]", "[C71585][b][c]", "[4B0082][b][c]",
        "[B22222][b][c]", "[228B22][b][c]", "[8B008B][b][c]", "[483D8B][b][c]",
        "[556B2F][b][c]", "[800000][b][c]", "[008080][b][c]", "[000080][b][c]",
        "[800080][b][c]", "[808080][b][c]", "[A9A9A9][b][c]", "[D3D3D3][b][c]", "[F0F0F0][b][c]"
    ]
    return random.choice(color_list)   


def BaNneR():
    bN = [902000306 , 902000305 , 902000017 , 902000011 , 902000091 , 902000207 , 902050001 , 902050002 , 902050003 , 902050004 , 902050005 , 902050006]
    return random.choice(bN)

def GeT_Status(PLayer_Uid, K, V):
    PLayer_Uid = cZ(PLayer_Uid, Tp='Uid')
    if len(PLayer_Uid) == 8:
        Pk = f'080112080a04{PLayer_Uid}1005'
    elif len(PLayer_Uid) == 10:
        Pk = f"080112090a05{PLayer_Uid}1005"
    return iZ(Pk, '0f15', K, V)

def open_almih(K, V):
    packet_id = '1215'
    fields = {}
    fields[1] = 3
    fields[2] = {}
    fields[2][2] = 5
    fields[2][3] = "tr"
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def hed(K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 17
    fields[2] = {}
    fields[2][1] = int(14783394432)
    fields[2][2] = 1
    fields[2][3] = 1
    fields[2][4] = 43
    fields[2][5] = {}
    fields[2][8] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def Exit(id , K , V):
    packet_id = '0515'
    fields = {
        1: 7,
        2: {
            1: id
        }
        }
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def name_room(code, name, K, V):
    packet_id = '0E15'
    fields = {}
    fields[1] = 13
    fields[2] = {}
    fields[2][1] = int(code)
    fields[2][2] = color() + name
    fields[2][4] = 1
    fields[2][5] = 15
    fields[2][6] = 8
    fields[2][7] = 30
    fields[2][8] = 1
    fields[2][9] = 1
    fields[2][11] = 35670336
    fields[2][12] = 10757192
    fields[2][13] = 1
    fields[2][18] = {}
    fields[2][18][0] = 1
    fields[2][28] = 1104
    fields[2][30] = 1
    fields[2][35] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)
    
def start_not(K, V):
    packet_id = '0315'
    fields = {}
    fields[1] = 2
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def spam_sqwad(Uid, K, V):
    packet_id = '0515'
    import random
    same_value = random.choice([4096, 16384, 8192])    
    fields = {}
    fields[1] = 33
    fields[2] = {}
    fields[2][1] = int(Uid)
    fields[2][2] = "ME"
    fields[2][3] = 1
    fields[2][4] = 1
    fields[2][5] = bytes([1, 7, 9, 10, 11, 18, 25, 26, 32])
    fields[2][6] = "zIx"
    fields[2][7] = 330
    fields[2][8] = 1000
    fields[2][10] = "ME"
    fields[2][11] = bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56, 97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53])
    fields[2][12] = 1
    fields[2][13] = int(Uid)
    fields[2][14] = {}
    fields[2][14][1] = 2203434355
    fields[2][14][2] = 8
    fields[2][14][3] = "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    fields[2][16] = 1
    fields[2][17] = 1
    fields[2][18] = 312
    fields[2][19] = 46
    fields[2][23] = bytes([16, 1, 24, 1])
    fields[2][24] = 902000306
    fields[2][26] = ""
    fields[2][28] = ""
    fields[2][31] = {}
    fields[2][31][1] = 1
    fields[2][31][2] = same_value
    fields[2][32] = same_value
    fields[2][34] = {}
    fields[2][34][1] = int(Uid)
    fields[2][34][2] = 8
    fields[2][34][3] = bytes([15, 6, 21, 8, 10, 11, 19, 12, 17, 4, 14, 20, 7, 2, 1, 5, 16, 3, 13, 18])
    fields[10] = "en"
    fields[13] = {}
    fields[13][2] = 1
    fields[13][3] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)


def spam_hom(Uid, K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 2
    fields[2] = {}
    fields[2][1] = int(Uid)
    fields[2][2] = 'ME'
    fields[2][4] = 16
    fields[2][5] = 'freefire://process?action=group_invite&group_id=9CDC4F20F2859F5E96B154BFBEA29F27&region=ME&secret_code=1784058402391435393_9xcxhezskn&version=OB54'
    fields[2][6] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def spai_sqiwad(Uid, K, V):
    packet_id = '0515'
    import random
    same_value = random.choice([4096, 16384, 8192])    
    fields = {}
    fields[1] = 33
    fields[2] = {}
    fields[2][1] = int(Uid)
    fields[2][2] = "ME"
    fields[2][3] = 1
    fields[2][4] = 1
    fields[2][5] = bytes([1, 7, 9, 10, 11, 18, 25, 26, 32])
    fields[2][6] = "zIx"
    fields[2][7] = 330
    fields[2][8] = 1000
    fields[2][10] = "ME"
    fields[2][11] = bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56, 97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53])
    fields[2][12] = 1
    fields[2][13] = int(Uid)
    fields[2][14] = {}
    fields[2][14][1] = 2203434355
    fields[2][14][2] = 8
    fields[2][14][3] = "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    fields[2][16] = 1
    fields[2][17] = 1
    fields[2][18] = 312
    fields[2][19] = 46
    fields[2][23] = bytes([16, 1, 24, 1])
    fields[2][24] = 902000306
    fields[2][26] = ""
    fields[2][28] = ""
    fields[2][31] = {}
    fields[2][31][1] = 1
    fields[2][31][2] = same_value
    fields[2][32] = same_value
    fields[2][34] = {}
    fields[2][34][1] = int(Uid)
    fields[2][34][2] = 8
    fields[2][34][3] = bytes([15, 6, 21, 8, 10, 11, 19, 12, 17, 4, 14, 20, 7, 2, 1, 5, 16, 3, 13, 18])
    fields[10] = "en"
    fields[13] = {}
    fields[13][2] = 1
    fields[13][3] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)


def LaGx(K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 15
    fields[2] = {}
    fields[2][1] = 804266360
    fields[2][2] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def xStart(K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 9
    fields[2] = {}
    fields[2][1] = 804266360
    fields[2][7] = {}
    fields[2][7][1] = 'IDC4'
    fields[2][7][2] = 210
    fields[2][7][3] = 'ME'
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def start_lvl(K, V):
    packet_id = '0315'
    fields = {}
    fields[1] = 1
    fields[2] = {}
    fields[2][1] = {}
    fields[2][2] = 43
    fields[2][7] = {}
    fields[2][7][1] = 'IDC4'
    fields[2][7][2] = 281
    fields[2][7][3] = 'ME'
    fields[2][8] = 1
    fields[2][9] = {}
    fields[2][11] = 1
    fields[2][12] = {}
    fields[2][12][1] = '08FBA33C71181AA802091D0111110000009300030090003C6CD1584013D524404676251411010308d1da79bf0e748c3f6a3ba7c7000000ff07080502cacfa16d'
    fields[2][12][2] = 198
    fields[2][12][3] = b'~^XT\x11\x02\x04H[\x07\x06\x0fS\x02\x05\x07\x05U\x0c\x01\x02\x02\nVV\x01\x04\x05Q\x06\x01\x01Q[\x03\x05PSUW\x17\x08\x02O}ZDEK\x1b\x04\x18\x08\x1a\x10\t\x05H\x1a@c~X^CwyYRHgpD\x1fP\\K\rUCBh_ee\x04\x10\x02D\x1c\x01^u\x1cf\x05Kz\x06[`Ccp\x1cYQKFIOUg\x01\x03\x07\t\x17\x08\x00OP\x03~g|k\x07\x05w\x04WVZRE\x05\x04fL\x0cKqBA\rt{\x0e\x17\x0cE\\K`\x0e{G\x0bq\x06ahXUP\x00qXBZ^NH{Im\\G\x0c\x11\x01HCwFRI\x0faPFyCPQCrnUXz}rePT\x03{K\n\x17\x08Neusmy\x01@\x04d|[F\x02[P|EQUd\tcg\x00\\xf\x0e\x1b\x06\x0cMzuR\rnpta\x06cDzR\x0cDm^VjUGsS\x04[\x07p\x0e\x10\x0bKw\x1e~U~Lr|{L[uivtUM|bgPvugwvS\t\x1a\x07O\t{\x1bgYc~{@Dgpa\\W~~B\x1fJ\x01q\x08n\x1bh]\x0e\x17\x06\tO\x07j\x07\x0cpgdsaJrwltz\x7fA\x03uBkzI\x0c]]x\x0f\x10\x01H[\x02|JTsuAZe`\x0et^mNX\x01fEywLf\x03\rr\t'
    fields[2][12][4] = '}WYQ'
    fields[2][12][6] = 11
    fields[2][12][7] = {}
    fields[2][12][8] = '1.128.11'
    fields[2][12][9] = 3
    fields[2][12][10] = 1
    fields[2][12][11] = {}
    fields[2][20] = {}
    fields[2][20][1] = 21
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def ban_chat(id, K, V):
    packet_id = '1215'
    fields = {
        1: 3,
        2: {
            1: int(id),
            3: "fr",
            4: "1750728024661459697_3qind8eeqs",
        }
    }
    return iZ(str(gZ(fields).hex()), packet_id, K, V)


def chat_room(id_room, code, K, V):
    packet_id = '1215'
    fields = {}
    fields[1] = 3
    fields[2] = {}
    fields[2][1] = int(id_room)
    fields[2][2] = 3
    fields[2][3] = 'ar'
    fields[2][4] = int(code)
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def chat(owner_id, code, K, V):
    packet_id = '1215'
    fields = {}
    fields[1] = 3
    fields[2] = {}
    fields[2][1] = int(owner_id)
    fields[2][3] = 'ar'
    fields[2][4] = int(code)
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def msg_in_team(id_bot, owner_id, msg, K, V):
    packet_id = '1215'
    fields = {}
    fields[1] = 1
    fields[2] = {}
    fields[2][1] = int(id_bot)
    fields[2][2] = int(owner_id)
    fields[2][4] = color() + msg
    fields[2][5] = 1756580149
    fields[2][7] = 2
    fields[2][8] = 904990072
    fields[2][9] = {}
    fields[2][9][1] = "zIX"
    fields[2][9][2] = BaNneR()
    fields[2][9][4] = 330
    fields[2][9][5] = 827001005
    fields[2][9][8] = "zIX"
    fields[2][9][10] = 1
    fields[2][9][11] = 1
    fields[2][9][13] = {}
    fields[2][9][13][1] = 2
    fields[2][9][14] = {}
    fields[2][9][14][1] = 1158053040
    fields[2][9][14][2] = 8
    fields[2][9][14][3] = "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    fields[2][10] = "en"
    fields[2][13] = {}
    fields[2][13][2] = 2
    fields[2][13][3] = 1
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

    
def skins(skin_id, K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 88
    fields[2] = {}
    fields[2][1] = {}
    fields[2][1][1] = int(skin_id)
    fields[2][1][2] = 1
    fields[2][2] = 2
    return iZ(str(gZ(fields).hex()), packet_id, K, V)
    
def ghost(player_id, name, code, key, iv):
    packet_id = '0515'
    fields = {}
    fields[1] = 61
    fields[2] = {}
    fields[2][1] = int(player_id)
    fields[2][2] = {}
    fields[2][2][1] = int(player_id)
    fields[2][2][2] = 1159
    fields[2][2][3] = f"[b][c][ff0000]{name}"
    fields[2][2][5] = 12
    fields[2][2][6] = 999
    fields[2][2][7] = 1
    fields[2][2][8] = {}
    fields[2][2][8][2] = 1
    fields[2][2][8][3] = 1
    fields[2][2][9] = 3
    fields[2][3] = code
    return iZ(str(gZ(fields).hex()), packet_id, key, iv)

def OpEnSq(K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 1
    fields[2] = {}
    fields[2][2] = '011d'
    fields[2][3] = 1
    fields[2][4] = 3
    fields[2][5] = 'ar'
    fields[2][8] = {}
    fields[2][8][1] = 'IDC4'
    fields[2][8][2] = 145
    fields[2][8][3] = 'ME'
    fields[2][9] = 1
    fields[2][10] = '01030407090a0b12191a201d2729'
    fields[2][11] = 1
    fields[2][13] = 1
    fields[2][14] = {}
    fields[2][14][1] = {}
    fields[2][14][1][6] = 56
    fields[2][14][2] = 731
    fields[2][14][3] = '745d59541601024c01015f02020d0905030304570608570d57060d53540402025f5707545301060613050645775945454c18021c051e1a0306491a4760785c53477d735a53486073421b5d5841075642426f5c63610914084e1f005e721f6001467e0c51634263771f5f554642434556660104040f13050445636e74634379505365047256665e405459657766510f615a5250420d11084858416a0d7a470c720065655c5f5a0370584559584a457f43675f460c16024e477a4258430c6050417a45545c47786456597a7a7163545907714109160849667377607d0b4a07657c5c45045f5d784f5b5665096464065875620411050d4d7f7444766661406a6205545d5b5f74507e0b0b535c67580877607d0a1a0148761e795678487f7871465874697177534971666d5a7574677075550d17034503781a675e60787f4d406d7a625d57797d441b47057b026d1a685a0d1102044b0d60040d706067756547767d66777b7f46007346667e43065e5c780813074c5606764057727546596364037054674d590161467f73416209077108'
    fields[2][14][4] = 'w]ZP'
    fields[2][14][6] = 11
    fields[2][14][7] = '140b7d71715b751011'
    fields[2][14][8] = '1.126.8'
    fields[2][14][9] = 3
    fields[2][14][10] = 2
    fields[2][14][11] = '0362625351363559382b505637416456324b796f566c6364724541566d46795954394b384445494d7a4b646d4b4231562f2b5a727577754a307847426c36712b38683863796b56447967524f4e3676493259347a646974684371364b73464d33724e534a4c4274594f3256565a5465786235484c324c39544a7652514c55374a525663696154544d46776e594e4b4c35353150336c5831475150635668615a77396251674b4d30395a4b6a2f4d675a38656d66757a6e4b356f5a6734367841626a7761363273366235636469637867386a6d4e4944594c383638686e756c3044316a4e445636444a4a69614758456154782b5450696c6f69476f58333638497234563266697a63783934436f5562735039765855683438356a626233356a717a5577504365554c55776374534574456d68426c3957453943524873422b76504a39704863323479517a70446c74644779536f6a6a4f573166433343413733374e617255546d734a70355431686b35635853307134557a6f7a6b75684b6d42423067354f4563634b627a68506c585943712f666a59767531624174504d766437486f4e6e39696e53767679796c6156386e315837636b7978384575626b5868414734565069425961556a75667a2b75675a474164356872324c3156615434613143485745702f6b446142364849434b756f705770706c703151373265463252744f62544957487775305a6753474659514266396f6e48744e7a5035336e72457072366f6c5349455354393839414f494858313471384d4a5763546d514267486d6c3456454c617354426d6f2b36764149525752783664617256692f345147566f4c785944593359477a366e513d3d'
    fields[2][19] = 329
    fields[2][21] = '374f5219'
    fields[2][24] = {}
    fields[2][24][1] = 21
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def Sq_bot(Nu, Uid, K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 17
    fields[2] = {}
    fields[2][1] = int(Uid)
    fields[2][2] = 1
    fields[2][3] = int(Nu - 1)
    fields[2][4] = 62
    fields[2][5] = "\u001a"
    fields[2][8] = 5
    fields[2][13] = 329
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def emote(emote_id, player_id, owner_id, K, V):
    packet_id = '0515'
    fields = {}
    fields[1] = 21
    fields[2] = {}
    fields[2][1] = int(owner_id)
    fields[2][2] = 909000001
    fields[2][5] = {}
    fields[2][5][1] = int(player_id)
    fields[2][5][3] = int(emote_id)
    return iZ(str(gZ(fields).hex()), packet_id, K, V)

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = Fix_PackEt(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def _V(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            break
        s += 7
    return r, i

def PrOtO(hx):
    b, i, R = bytes.fromhex(hx), 0, {}
    while i < len(b):
        H, i = _V(b, i)
        F, T = H >> 3, H & 7
        if T == 0:
            R[F], i = _V(b, i)
        elif T == 2:
            L, i = _V(b, i)
            S = b[i:i+L]
            i += L
            try:
                R[F] = S.decode()
            except:
                try:
                    R[F] = PrOtO(S.hex())
                except:
                    R[F] = S
        elif T == 5:
            R[F] = int.from_bytes(b[i:i+4], 'little')
            i += 4
        else:
            raise ValueError(f'Unknown wire type: {T}')
    return R

def iZ(pk, n, k, v):
    pkEnc = bZ(pk, k, v)
    _ = hZ(int(len(pkEnc) // 2))
    if len(_) == 2:
        header = n + "000000"
    elif len(_) == 3:
        header = n + "00000"
    elif len(_) == 4:
        header = n + "0000"
    elif len(_) == 5:
        header = n + "000"
    return bytes.fromhex(header + _ + pkEnc)