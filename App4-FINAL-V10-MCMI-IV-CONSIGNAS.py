
import hashlib
import json
import random
import sqlite3
import string
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import streamlit as st

st.set_page_config(page_title="Evaluaciones Psicologicas Forenses - V10 MCMI-IV + Consignas", page_icon="⚖️", layout="wide")
hide_style = """<style>#MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}</style>"""
st.markdown(hide_style, unsafe_allow_html=True)

CONTRASEÑA_MAESTRA = "MiClavePericial2026"
DB_NAME = str(Path(__file__).parent / "forense_seguro.db")
TZ = ZoneInfo("America/Argentina/Buenos_Aires")

def init_db():
  conn = sqlite3.connect(DB_NAME, check_same_thread=False)
  cursor = conn.cursor()
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS evaluaciones_periciales (
            token TEXT PRIMARY KEY,
            estado TEXT,
            datos_persona TEXT,
            evaluaciones TEXT,
            ip_acceso TEXT,
            user_agent TEXT,
            hash_anterior TEXT,
            hash_bloque TEXT,
            fecha_creacion TEXT,
            fecha_actualizacion TEXT
        )
    """)
  conn.commit()
  conn.close()

init_db()

def cargar_datos_db():
  conn = sqlite3.connect(DB_NAME, check_same_thread=False)
  cursor = conn.cursor()
  cursor.execute("SELECT token, estado, datos_persona, evaluaciones, ip_acceso, user_agent, hash_bloque, fecha_creacion, fecha_actualizacion FROM evaluaciones_periciales")
  rows = cursor.fetchall()
  conn.close()
  data={}
  for row in rows:
    token, estado, dp, evals, ip, ua, h_bloque, f_crea, f_act = row
    try: dp_json = json.loads(dp) if dp else None
    except: dp_json = {"raw": dp}
    try: evals_json = json.loads(evals) if evals else {}
    except: evals_json = {}
    data[token] = {"estado": estado if estado else "activa", "datos_persona": dp_json, "evaluaciones": evals_json, "ip_acceso": ip, "user_agent": ua, "hash_bloque": h_bloque, "fecha_creacion": f_crea, "fecha_actualizacion": f_act}
  return data

def guardar_token_db(token, info_dict):
  conn = sqlite3.connect(DB_NAME, check_same_thread=False)
  cursor = conn.cursor()
  cursor.execute("SELECT hash_bloque FROM evaluaciones_periciales ORDER BY rowid DESC LIMIT 1")
  ultimo = cursor.fetchone()
  hash_prev = ultimo[0] if ultimo and ultimo[0] else "GENESIS_BLOCK_FORENSE"
  payload_str = f"{token}-{json.dumps(info_dict.get('evaluaciones'))}-{info_dict.get('ip_acceso', '')}-{hash_prev}"
  hash_actual = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
  ahora = datetime.now(TZ).isoformat()
  cursor.execute("""
        INSERT OR REPLACE INTO evaluaciones_periciales 
        (token, estado, datos_persona, evaluaciones, ip_acceso, user_agent, hash_anterior, hash_bloque, fecha_creacion, fecha_actualizacion)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT fecha_creacion FROM evaluaciones_periciales WHERE token=?), ?), ?)
    """, (token, info_dict.get("estado", "activa"), json.dumps(info_dict.get("datos_persona"), ensure_ascii=False), json.dumps(info_dict.get("evaluaciones", {}), ensure_ascii=False), info_dict.get("ip_acceso", "Desconocida"), info_dict.get("user_agent", "Desconocido"), hash_prev, hash_actual, token, ahora, ahora))
  conn.commit()
  conn.close()

def eliminar_token_db(token):
  conn = sqlite3.connect(DB_NAME, check_same_thread=False)
  cursor = conn.cursor()
  cursor.execute("DELETE FROM evaluaciones_periciales WHERE token = ?", (token,))
  conn.commit()
  conn.close()

def obtener_metadatos_conexion():
  try:
    from streamlit.web.server.websocket_headers import _get_websocket_headers
    headers = _get_websocket_headers()
    if headers:
      ip = headers.get("X-Forwarded-For", headers.get("Remote-Addr", "127.0.0.1"))
      if "," in ip: ip = ip.split(",")[0].strip()
      ua = headers.get("User-Agent", "Desconocido")
      return ip, ua
  except: pass
  return "IP_ONLINE", "Navegador_Estandar"

def generar_token_unico(longitud=6):
  caracteres = string.ascii_uppercase + string.digits
  codigo = "".join(random.choice(caracteres) for _ in range(longitud))
  return f"EVAL-{codigo}"





# ==================== PARCHE CLOUD V15 - SAFE NON-BLOCKING ====================
# V15: no bloquea el arranque aunque npoint falle o Malwarebytes lo bloquee
import requests as req_lib
import json as json_lib

CLOUD_MODE = "sqlite"
NPOINT_URL = None

try:
    NPOINT_URL = st.secrets.get("NPOINT_URL", None)
except:
    NPOINT_URL = None

if NPOINT_URL:
    CLOUD_MODE = "npoint"

# Guardamos originales primero (ya existen)
cargar_datos_db_original = cargar_datos_db
guardar_token_db_original = guardar_token_db
eliminar_token_db_original = eliminar_token_db

def cargar_datos_db_cloud():
    if CLOUD_MODE == "npoint" and NPOINT_URL:
        try:
            # Timeout muy corto para no colgar la ruedita
            r = req_lib.get(NPOINT_URL, timeout=3)
            if r.status_code == 200:
                j = r.json()
                return j.get("evaluaciones", j) if isinstance(j, dict) else {}
        except Exception as e:
            # Si falla (Malwarebytes bloquea, timeout, etc), usa sqlite local y no rompe
            pass
    # Fallback siempre funciona
    try:
        return cargar_datos_db_original()
    except:
        return {}

def guardar_token_db_cloud(token, info_dict):
    # Siempre guarda local primero (rápido)
    try:
        guardar_token_db_original(token, info_dict)
    except:
        pass
    # Luego intenta nube sin bloquear mucho
    if CLOUD_MODE == "npoint" and NPOINT_URL:
        try:
            r = req_lib.get(NPOINT_URL, timeout=3)
            all_data = {}
            if r.status_code == 200:
                j = r.json()
                all_data = j.get("evaluaciones", j) if isinstance(j, dict) else {}
            all_data[token] = {
                "estado": info_dict.get("estado", "activa"),
                "datos_persona": info_dict.get("datos_persona"),
                "evaluaciones": info_dict.get("evaluaciones", {}),
                "ip_acceso": info_dict.get("ip_acceso"),
                "user_agent": info_dict.get("user_agent"),
                "hash_bloque": info_dict.get("hash_bloque"),
                "fecha_actualizacion": datetime.now(TZ).isoformat(),
                "fecha_creacion": info_dict.get("fecha_creacion") or datetime.now(TZ).isoformat()
            }
            req_lib.post(NPOINT_URL, json={"evaluaciones": all_data}, timeout=3)
        except:
            pass

def eliminar_token_db_cloud(token):
    try:
        eliminar_token_db_original(token)
    except:
        pass
    if CLOUD_MODE == "npoint" and NPOINT_URL:
        try:
            r = req_lib.get(NPOINT_URL, timeout=3)
            if r.status_code == 200:
                j = r.json()
                all_data = j.get("evaluaciones", j) if isinstance(j, dict) else {}
                if token in all_data:
                    del all_data[token]
                    req_lib.post(NPOINT_URL, json={"evaluaciones": all_data}, timeout=3)
        except:
            pass

cargar_datos_db = cargar_datos_db_cloud
guardar_token_db = guardar_token_db_cloud
eliminar_token_db = eliminar_token_db_cloud
# ==================== FIN PARCHE V15 ====================

if "perito_autenticado" not in st.session_state:
  st.session_state["perito_autenticado"] = False
if "token_actual" not in st.session_state:
  st.session_state["token_actual"] = None
if "test_enviado" not in st.session_state:
  st.session_state["test_enviado"] = False
if "data_version" not in st.session_state:
  st.session_state["data_version"] = 0

TESTS_DISPONIBLES = [
    "LSB-50 (Listado de Sintomas Breve)",
    "MCMI-III (Inventario Clinico Multiaxial de Millon-III)",
    "MCMI-IV (Inventario Clinico Multiaxial de Millon-IV) - VIGENTE DSM-5",
    "CUIDA (Evaluacion de Adoptantes, Cuidadores, Tutores y Mediadores)",
    "STAI (Cuestionario de Ansiedad Estado-Rasgo)",
    "BDI-II (Inventario de Depresion de Beck)",
    "PAI (Inventario de Evaluacion de la Personalidad)",
]

# ==================== CONSIGNA OFICIAL POR TEST - PARA HOJA DEL EVALUADO ====================
CONSIGNA_TESTS = {
    "LSB-50": """
    **A continuación encontrará una lista de problemas y molestias que a veces tiene la gente.**
    Por favor, lea cada una atentamente y decida en qué medida le ha molestado cada problema durante la última semana, incluyendo el día de hoy.
    - 0 = Nada | 1 = Un poco | 2 = Moderadamente | 3 = Bastante | 4 = Mucho
    """,
    "MCMI-III": """
    **Lea cada enunciado y decida si es Verdadero o Falso en su caso.** 
    Trate de no dejar ninguna frase sin contestar. Si no está seguro, decida según lo que sea más verdadero para usted en la actualidad.
    No hay respuestas buenas o malas. Responda con sinceridad.
    - Opciones: V = Verdadero / F = Falso
    """,
    "MCMI-IV": """
    **MCMI-IV - Inventario Clínico Multiaxial de Millon IV (195 ítems - VIGENTE DSM-5).**
    Lea cada afirmación y decida si es Verdadera o Falsa según usted es habitualmente. 
    Esta es la versión actualizada al DSM-5. Incluye 15 escalas de personalidad, 10 escalas clínicas y 5 índices de validez.
    - Opciones: V = Verdadero / F = Falso
    - Tiempo: 25-35 min
    """,
    "CUIDA": """
    **A continuación se le presentarán afirmaciones sobre su forma de ser y actuar en situaciones de cuidado.**
    Indique su grado de acuerdo.
    - 1 = En total desacuerdo | 2 = En desacuerdo | 3 = De acuerdo | 4 = Totalmente de acuerdo
    Evalúa 14 variables relevantes para adopción, custodia y cuidado.
    """,
    "STAI": """
    **El STAI consta de dos partes:**
    **PARTE 1 - ESTADO (E):** Cómo se siente AHORA MISMO, en este momento. 0=Nada, 1=Algo, 2=Bastante, 3=Mucho
    **PARTE 2 - RASGO (R):** Cómo se siente EN GENERAL, habitualmente. 0=Casi nunca, 1=A veces, 2=A menudo, 3=Casi siempre
    """,
    "BDI-II": """
    **En este cuestionario hay grupos de 4 afirmaciones.** Lea cada grupo y elija la frase que mejor describa cómo se ha sentido durante las últimas 2 semanas, incluyendo hoy.
    Si varios enunciados le parecen igualmente apropiados, elija el número más alto.
    """,
    "PAI": """
    **Lea cada afirmación y decida si es Falsa, Ligeramente Verdadera, Bastante Verdadera o Totalmente Verdadera.**
    - F = Falso | LV = Ligeramente Verdadero | BV = Bastante Verdadero | TV = Totalmente Verdadero
    """
}

TIEMPO_ESTIMADO = {
    "LSB-50": "5-8 min", "MCMI-III": "25-30 min", "MCMI-IV": "25-35 min",
    "CUIDA": "35-45 min", "STAI": "8-10 min", "BDI-II": "5-7 min", "PAI": "40-55 min"
}

def render_consigna(nombre_test_key):
    consigna = CONSIGNA_TESTS.get(nombre_test_key, "Siga las instrucciones del test.")
    tiempo = TIEMPO_ESTIMADO.get(nombre_test_key, "N/D")
    st.markdown(f"""
    <div style="background-color:#eef6ff; padding:16px; border-radius:12px; border-left: 6px solid #1f77b4; margin-bottom:12px;">
    <b>📋 CONSIGNA OFICIAL - {nombre_test_key}</b><br><br>
    {consigna}<br>
    <b>⏱ Tiempo estimado:</b> {tiempo}<br>
    <b>🔒 Responda con sinceridad, no hay respuestas correctas o incorrectas para fines periciales.</b>
    </div>
    """, unsafe_allow_html=True)

# --- MCMI-IV 195 items placeholder (reemplazar con texto oficial licenciado si cuentas con licencia) ---
ITEMS_MCMI_IV = [f"{i}. [MCMI-IV Item {i} - Texto oficial licenciado TEA/Pearson - 195 items DSM-5]" for i in range(1, 196)]



ITEMS_LSB50 = [
    "1. Mi corazón palpita o va muy deprisa.",
    "2. Me siento triste.",
    "3. Tengo ganas de romper o destruir algo.",
    "4. Siento nerviosismo o agitación interior.",
    "5. Tengo mareos o sensaciones de desmayo.",
    "6. Me preocupa la dejadez y el descuido.",
    "7. Tengo que comprobar una y otra vez todo lo que hago.",
    "8. Me cuesta tomar decisiones.",
    "9. Me irrito o enfado por cualquier cosa.",
    "10. Siento miedo en la calle o en espacios abiertos.",
    "11. Tengo dolores de cabeza.",
    "12. Me siento decaído o falto de fuerzas.",
    "13. Me despierto por la madrugada.",
    "14. Duermo inquieto o me despierto mucho por la noche.",
    "15. Doy vueltas a palabras o ideas que no consigo quitarme de la cabeza.",
    (
        "16. Me siento incomodo o vergonzoso cuando estoy en reuniones o con"
        " gente."
    ),
    "17. Me vienen ideas de acabar con mi vida.",
    "18. Tengo miedo sin motivo.",
    "19. Tengo molestias digestivas o náuseas.",
    "20. Siento hormigueo o se me duerme alguna parte de mi cuerpo.",
    "21. Veo mi futuro sin esperanza.",
    "22. Me da miedo estar solo.",
    "23. Tengo ataques de ira que no puedo controlar.",
    "24. Me siento incomprendido o no me hacen caso.",
    "25. Me da miedo salir de casa sólo.",
    "26. Me parece que otras personas me observan o hablan de mí.",
    "27. Me cuesta dormirme.",
    "28. Tengo sentimiento de culpa.",
    "29. Me siento incómodo comiendo o bebiendo en público.",
    "30. Me siento herido con facilidad.",
    "31. Me siento incapaz de hacer las cosas o terminar las tareas.",
    "32. No siento interés por nada.",
    (
        "33. Tengo manías como repetir cosas innecesariamente (tocar algo,"
        " lavarme, comprobar algo, etc.)."
    ),
    "34. Me vienen ideas o imágenes que me dan miedo.",
    "35. Me siento temeroso.",
    (
        "36. Tengo que hacer las cosas muy despacio para estar seguro de que lo"
        " hago bien."
    ),
    "37. Me siento solo.",
    "38. Me siento inferior a los demás.",
    "39. Lloro con facilidad.",
    "40. Me siento solo, aunque tenga compañía.",
    "41. Me da por gritar o tirar las cosas.",
    "42. Me siento inútil o poco valioso.",
    "43. Me duelen los músculos.",
    "44. Discuto con frecuencia.",
    "45. Tengo dolores en el corazón o en el pecho.",
    "46. Me dan ahogos o me cuesta respirar.",
    (
        "47. Tengo que evitar ciertas cosas, lugares o actividades porque me"
        " dan miedo."
    ),
    "48. Me dan ganas de golpear o hacer daño a alguien.",
    "49. Siento que todo requiere un gran esfuerzo.",
    "50. Tengo presentimientos de que va a pasar algo malo.",
]

OPCIONES_LSB50 = {
    0: "0 - Nada",
    1: "1 - Poco",
    2: "2 - Moderadamente",
    3: "3 - Bastante",
    4: "4 - Mucho",
}

ITEMS_CASULLO = [
    "1. Enfermedad física propia, seria, importante",
    "2. Enfermedad física seria de algún hermano/a",
    "3. Enfermedad física seria del padre",
    "4. Enfermedad física seria de la madre",
    "5. Enfermedad física seria de algún amigo/a",
    "6. Problemas psicológicos personales importantes",
    "7. Enfermedad psíquica de algún hermano/a",
    "8. Enfermedad psíquica del padre",
    "9. Enfermedad psíquica de la madre",
    "10. Enfermedad psíquica de algún pariente",
    "11. Enfermedad psíquica de algún amigo/a",
    "12. Muerte del padre",
    "13. Muerte de la madre",
    "14. Muerte de algún hermano/a",
    "15. Muerte de algún abuelo",
    "16. Desaparición de algún familiar (no saber dónde está)",
    "17. Desaparición de algún amigo/a (no saber dónde está)",
    "18. Divorcio o separación de los padres",
    "19. Divorcio o separación de algún hermano/a",
    "20. Embarazo no deseado",
    "21. Aborto",
    "22. Violación",
    "23. Alguno de los padres despedido o sin empleo",
    "24. Alguna experiencia sexual desagradable, traumática",
    "25. Mudanzas",
    "26. Abuso de alcohol o drogas de algún hermano/a",
    "27. Abuso de alcohol o drogas de alguno de los padres",
    "28. Problemas personales en relación con alcohol o drogas",
    "29. Estar separado/a de un ser querido",
    "30. Muerte de algún amigo/a",
    "31. Serios problemas económicos familiares",
    "32. Problemas familiares graves",
    "33. Problemas personales con algún docente",
    "34. Problemas para aprender en la escuela",
    "35. Ruptura de noviazgo o pareja",
    "36. Problemas que implicaron la participación de la policía",
    "37. Dificultades para tener amigos/as",
    "38. Problemas de fe (crisis religiosa)",
    "39. Haber sufrido un accidente serio",
    "40. Intentar quitarme la vida",
    "41. Divorcio o separación personal",
    "42. Tener dificultades para formar pareja",
    "43. Tener dificultades para conseguir trabajo",
    "44. Confusión vocacional, no saber qué estudiar",
    "45. Problemas de disciplina en la escuela",
    "46. Sentirme amenazado/a o perseguido/a por alguien",
    "47. No poder conservar por mucho tiempo un trabajo",
    "48. Enterarme de que me adoptaron",
    "49. Haber sido golpeado/a, duramente castigado/a",
    "50. Haber pensado en quitarme la vida",
]

OPCIONES_CASULLO = {
    1: "1 - Nada",
    2: "2 - Poco",
    3: "3 - Algo",
    4: "4 - Bastante",
    5: "5 - Mucho",
}

ITEMS_MCMIIII = [
    "1. Últimamente parece que me quedo sin fuerzas, incluso por la mañana.",
    "2. Me parece muy bien que haya normas porque son una buena guía a seguir.",
    "3. Disfruto haciendo tantas cosas diferentes que no puedo decidir por cuál empezar.",
    "4. Gran parte del tiempo me siento débil y cansado.",
    "5. Sé que soy superior a los demás, por eso no me importa lo que piense la gente.",
    "6. La gente nunca ha reconocido suficientemente las cosas que he hecho.",
    "7. Si mi familia me presiona, es probable que me enfade y me resista a hacer lo que ellos quieren.",
    "8. La gente se burla de mí a mis espaldas, hablando de lo que hago o parezco.",
    "9. Frecuentemente critico mucho a la gente que me irrita.",
    "10. Raramente exteriorizo las pocas emociones que suelo tener.",
    "11. Me resulta difícil mantener el equilibrio cuando camino.",
    "12. Muestro mis emociones fácil y rápidamente.",
    "13. En el pasado, mis hábitos de tomar drogas me han causado problemas a menudo.",
    "14. Algunas veces puedo ser bastante duro y desagradable con mi familia.",
    "15. Las cosas que hoy van bien no durarán mucho tiempo.",
    "16. Soy una persona muy agradable y sumisa.",
    "17. Cuando era adolescente, tuve muchos problemas por mi mal comportamiento en el colegio.",
    "18. Tengo miedo a acercarme mucho a otra persona porque podría acabar siendo ridiculizado o avergonzado.",
    "19. Parece que elijo amigos que terminan tratándome mal.",
    "20. He tenido pensamientos tristes gran parte de mi vida desde que era niño.",
    "21. Me gusta coquetear con las personas del otro sexo.",
    "22. Soy una persona muy variable y cambio de opiniones y sentimientos continuamente.",
    "23. Beber alcohol nunca me ha causado verdaderos problemas en mi trabajo.",
    "24. Hace unos años comencé a sentirme un fracasado.",
    "25. Me siento culpable muy a menudo sin ninguna razón.",
    "26. Los demás envidian mis capacidades.",
    "27. Cuando puedo elegir, prefiero hacer las cosas solo.",
    "28. Pienso que el comportamiento de mi familia debería ser estrictamente controlado.",
    "29. La gente normalmente piensa que soy una persona reservada y seria.",
    "30. Últimamente he comenzado a sentir deseos de destrozar cosas.",
    "31. Creo que soy una persona especial y merezco que los demás me presten una particular atención.",
    "32. Siempre estoy buscando hacer nuevos amigos y conocer gente nueva.",
    "33. Si alguien me criticase por cometer un error, rápidamente le señalaría sus propios errores.",
    "34. Últimamente he perdido los nervios.",
    "35. A menudo renuncio a hacer cosas porque temo no hacerlas bien.",
    "36. Muchas veces me dejo llevar por mis emociones de ira y luego me siento terriblemente culpable por ello.",
    "37. Muy a menudo pierdo mi capacidad para percibir sensaciones en partes de mi cuerpo.",
    "38. Hago lo que quiero sin preocuparme de las consecuencias que tenga en los demás.",
    "39. Tomar las llamadas \"drogas ilegales\" puede ser imprudente, pero reconozco que en el pasado las he necesitado.",
    "40. Creo que soy una persona miedosa e inhibida.",
    "41. He hecho impulsivamente muchas cosas estúpidas que han llegado a causarme grandes problemas.",
    "42. Nunca perdono un insulto ni olvido una situación embarazosa que alguien me haya causado.",
    "43. A menudo me siento triste o tenso, inmediatamente después de que me haya pasado algo bueno.",
    "44. Ahora me siento terriblemente deprimido y triste gran parte del tiempo.",
    "45. Siempre hago lo posible por complacer a los demás, incluso a quienes no me gustan.",
    "46. Siempre he sentido menos interés por el sexo que la mayoría de la gente.",
    "47. Siempre tiendo a culparme a mí mismo cuando las cosas salen mal.",
    "48. Hace mucho tiempo decidí que lo mejor es tener poco que ver con la gente.",
    "49. Desde niño, siempre he tenido que tener cuidado con la gente que intentaba engañarme.",
    "50. No soporto a las personas influyentes que siempre piensan que pueden hacer las cosas mejor que yo.",
    "51. Cuando las cosas son aburridas, me gusta provocar algo interesante o divertido.",
    "52. Tengo un problema con el alcohol que nos ha creado dificultades a mi familia y a mí.",
    "53. Los castigos nunca me han impedido hacer lo que yo quería.",
    "54. Muchas veces me siento muy alegre y animado sin ninguna razón.",
    "55. En las últimas semanas me he sentido agotado sin ningún motivo especial.",
    "56. Últimamente me he sentido muy culpable porque ya no soy capaz de hacer nada bien.",
    "57. Pienso que soy una persona muy sociable y extravertida.",
    "58. Me he vuelto muy nervioso en las últimas semanas.",
    "59. Controlo muy bien mi dinero para estar preparado en caso de necesidad.",
    "60. Simplemente, no he tenido la suerte que otros han tenido en la vida.",
    "61. Algunas ideas me dan vueltas en la cabeza una y otra vez y no desaparecen.",
    "62. Desde hace uno o dos años, al pensar sobre la vida, me siento muy triste y desanimado.",
    "63. Mucha gente ha estado espiando mi vida privada durante años.",
    "64. No sé por qué pero, a veces, digo cosas crueles sólo para hacer sufrir a los demás.",
    "65. En el último año he cruzado el Atlántico en avión 30 veces.",
    "66. En el pasado, el hábito de abusar de las drogas me ha hecho faltar al trabajo.",
    "67. Tengo muchas ideas que son avanzadas para los tiempos actuales.",
    "68. Últimamente tengo que pensar las cosas una y otra vez sin ningún motivo.",
    "69. Evito la mayoría de las situaciones sociales porque creo que la gente va a criticarme o rechazarme.",
    "70. Muchas veces pienso que no merezco las cosas buenas que me pasan.",
    "71. Cuando estoy solo, a menudo noto cerca de mí la fuerte presencia de alguien que no puede ser visto.",
    "72. Me siento desorientado, sin objetivos, y no sé hacia dónde voy en la vida.",
    "73. A menudo dejo que los demás tomen por mí decisiones importantes.",
    "74. No puedo dormirme, y me levanto tan cansado como al acostarme.",
    "75. Últimamente sudo mucho y me siento muy tenso.",
    "76. Tengo una y otra vez pensamientos extraños de los que desearía poder librarme.",
    "77. Tengo muchos problemas para controlar el impulso de beber en exceso.",
    "78. Aunque esté despierto, parece que no me doy cuenta de la gente que está cerca de mí.",
    "79. Con frecuencia estoy irritado y de mal humor.",
    "80. Para mí es muy fácil hacer muchos amigos.",
    "81. Me avergüenzo de algunos de los abusos que sufrí cuando era joven.",
    "82. Siempre me aseguro de que mi trabajo esté bien planeado y organizado.",
    "83. Mis estados de ánimo cambian mucho de un día para otro.",
    "84. Me falta confianza en mí mismo para arriesgarme a probar algo nuevo.",
    "85. No culpo a quien se aprovecha de alguien que se lo permite.",
    "86. Desde hace algún tiempo me siento triste y deprimido y no consigo animarme.",
    "87. A menudo me enfado con la gente que hace las cosas lentamente.",
    "88. Cuando estoy en una fiesta nunca me aíslo de los demás.",
    "89. Observo a mi familia de cerca para saber en quién se puede confiar y en quién no.",
    "90. Algunas veces me siento confuso y molesto cuando la gente es amable conmigo.",
    "91. El consumo de \"drogas ilegales\" me ha causado discusiones con mi familia.",
    "92. Estoy solo la mayoría del tiempo y lo prefiero así.",
    "93. Algunos miembros de mi familia dicen que soy egoísta y que sólo pienso en mí mismo.",
    "94. La gente puede hacerme cambiar de ideas fácilmente, incluso cuando pienso que ya había tomado una decisión.",
    "95. A menudo irrito a la gente cuando les doy órdenes.",
    "96. En el pasado la gente decía que yo estaba muy interesado y apasionado por demasiadas cosas.",
    "97. Estoy de acuerdo con el refrán: \"Al que madruga Dios le ayuda\".",
    "98. Mis sentimientos hacia las personas importantes en mi vida muchas veces oscilan entre el amor y el odio.",
    "99. Cuando estoy en una reunión social, en grupo, casi siempre me siento tenso y cohibido.",
    "100. Supongo que no soy diferente de mis padres ya que, hasta cierto punto, me he convertido en un alcohólico.",
    "101. Creo que no me tomo muchas de las responsabilidades familiares tan seriamente como debería.",
    "102. Desde que era niño he ido perdiendo contacto con la realidad.",
    "103. Gente mezquina intenta con frecuencia aprovecharse de lo que he realizado o ideado.",
    "104. No puedo experimentar mucho placer porque no creo merecerlo.",
    "105. Tengo pocos deseos de hacer amigos íntimos.",
    "106. He tenido muchos periodos en mi vida en los que he estado tan animado y he consumido tanta energía que luego me he sentido muy bajo de ánimo.",
    "107. He perdido completamente mi apetito y la mayoría de las noches tengo problemas para dormir.",
    "108. Me preocupa mucho que me dejen solo y tenga que cuidar de mí mismo.",
    "109. El recuerdo de una experiencia muy perturbadora de mi pasado sigue apareciendo en mis pensamientos.",
    "110. El año pasado aparecí en la portada de varias revistas.",
    "111. Parece que he perdido el interés en la mayoría de las cosas que solía encontrar placenteras, como el sexo.",
    "112. He estado abatido y triste mucho tiempo en mi vida desde que era bastante joven.",
    "113. Me he metido en problemas con la ley un par de veces.",
    "114. Una buena manera de evitar los errores es tener una rutina para hacer las cosas.",
    "115. A menudo otras personas me culpan de cosas que no he hecho.",
    "116. He tenido que ser realmente duro con algunas personas para mantenerlas a raya.",
    "117. La gente piensa que, a veces, hablo sobre cosas extrañas o diferentes a las de ellos.",
    "118. Ha habido veces en las que no he podido pasar el día sin tomar drogas.",
    "119. La gente está intentando hacerme creer que estoy loco.",
    "120. Haría algo desesperado para impedir que me abandonase una persona que quiero.",
    "121. Sigo dándome atracones de comida un par de veces a la semana.",
    "122. Parece que echo a perder las buenas oportunidades que se cruzan en mi camino.",
    "123. Siempre me ha resultado difícil dejar de sentirme deprimido y triste.",
    "124. Cuando estoy solo y lejos de casa, a menudo comienzo a sentirme tenso y lleno de pánico.",
    "125. A veces las personas se molestan conmigo porque dicen que hablo mucho o demasiado deprisa para ellas.",
    "126. Hoy, la mayoría de la gente de éxito ha sido afortunada o deshonesta.",
    "127. No me involucro con otras personas a no ser que esté seguro de que les voy a gustar.",
    "128. Me siento profundamente deprimido sin ninguna razón que se me ocurra.",
    "129. Años después, todavía tengo pesadillas acerca de un acontecimiento que supuso una amenaza real para mi vida.",
    "130. Ya no tengo energía para concentrarme en mis responsabilidades diarias.",
    "131. Beber alcohol me ayuda cuando me siento deprimido.",
    "132. Odio pensar en algunas de las formas en las que se abusó de mí cuando era un niño.",
    "133. Incluso en los buenos tiempos, siempre he tenido miedo de que las cosas pronto fuesen mal.",
    "134. Algunas veces, cuando las cosas empiezan a torcerse en mi vida, me siento como si estuviera loco o fuera de la realidad.",
    "135. Estar solo, sin la ayuda de alguien cercano de quien depender, realmente me asusta.",
    "136. Sé que he gastado más dinero del que debiera comprando \"drogas ilegales\".",
    "137. Siempre compruebo que he terminado mi trabajo antes de tomarme un descanso para actividades de ocio.",
    "138. Noto que la gente está hablando de mí cuando paso a su lado.",
    "139. Se me da muy bien inventar excusas cuando me meto en problemas.",
    "140. Creo que hay una conspiración contra mí.",
    "141. Siento que la mayoría de la gente tiene una mala opinión de mí.",
    "142. Frecuentemente siento que no hay nada dentro de mí, como si estuviera vacío y hueco.",
    "143. Algunas veces me obligo a vomitar después de comer.",
    "144. Creo que me esfuerzo mucho por conseguir que los demás admiren las cosas que hago o digo.",
    "145. Me paso la vida preocupándome por una cosa u otra.",
    "146. Siempre me pregunto cuál es la razón real de que alguien sea especialmente agradable conmigo.",
    "147. Ciertos pensamientos vuelven una y otra vez a mi mente.",
    "148. Pocas cosas en la vida me dan placer.",
    "149. Me siento tembloroso y tengo dificultades para conciliar el sueño debido a dolorosos recuerdos de un hecho pasado que pasan por mi cabeza repetidamente.",
    "150. Pensar en el futuro al comienzo de cada día me hace sentir terriblemente deprimido.",
    "151. Nunca he sido capaz de librarme de sentir que no valgo nada para los demás.",
    "152. Tengo un problema con la bebida que he tratado de solucionar sin éxito.",
    "153. Alguien ha estado intentando controlar mi mente.",
    "154. He intentado suicidarme.",
    "155. Estoy dispuesto a pasar hambre para estar aún más delgado de lo que estoy.",
    "156. No entiendo por qué algunas personas me sonríen.",
    "157. No he visto un coche en los últimos diez años.",
    "158. Me pongo muy tenso con las personas que no conozco bien, porque pueden querer hacerme daño.",
    "159. Alguien tendría que ser bastante excepcional para entender mis habilidades especiales.",
    "160. Mi vida actual se ve todavía afectada por \"imágenes mentales de algo terrible que me pasó\".",
    "161. Parece que creo situaciones con los demás en las que acabo herido o me siento rechazado.",
    "162. A menudo me pierdo en mis pensamientos y me olvido de lo que está pasando a mi alrededor.",
    "163. La gente dice que soy una persona delgada, pero creo que mis muslos y mi trasero son demasiado grandes.",
    "164. Hay terribles hechos de mi pasado que vuelven repetidamente para perseguirme en mis pensamientos y sueños.",
    "165. No tengo amigos íntimos al margen de mi familia.",
    "166. Casi siempre actúo rápidamente y no pienso las cosas tanto como debiera.",
    "167. Tengo mucho cuidado en mantener mi vida como algo privado, de manera que nadie pueda aprovecharse de mí.",
    "168. Con mucha frecuencia oigo las cosas con tanta claridad que me molesta.",
    "169. Siempre estoy dispuesto a ceder en una riña o desacuerdo porque temo el enfado o rechazo de los demás.",
    "170. Repito ciertos comportamientos una y otra vez, algunas veces para reducir mi ansiedad y otras para evitar que pase algo malo.",
    "171. Recientemente he pensado muy en serio en quitarme de en medio.",
    "172. La gente me dice que soy una persona muy formal y moral.",
    "173. Todavía me aterrorizo cuando pienso en una experiencia traumática que tuve hace años.",
    "174. Aunque me da miedo hacer amistades, me gustaría tener más de las que tengo.",
    "175. A algunas personas que se supone que son mis amigos les gustaría hacerme daño."
]

OPCIONES_MCMI = ["Verdadero", "Falso"]

# OPCIONES_MMPI = ["Verdadero", "Falso"] ELIMINADO

ITEMS_CUIDA = [
    "1. Tengo problemas para dormir.",
    "2. Estoy satisfecho de cómo soy.",
    "3. Si alguien me insulta intento averiguar por qué lo hace.",
    "4. A veces juzgo a los demás sin conocerles.",
    "5. Me disgusta mi aspecto físico.",
    "6. Tengo cambios de humor con bastante facilidad.",
    "7. Me gusta reunirme con mis amigos y conversar.",
    "8. Siempre hago lo que digo.",
    "9. Hago todo lo posible por salirme con la mía.",
    "10. Me cuesta mucho participar en reuniones de grupo.",
    (
        "11. Ya no me resulta doloroso pensar en las cosas a las que he tenido"
        " que renunciar con los años."
    ),
    "12. Cuando voy de viaje evito relacionarme con otros viajeros.",
    "13. Me cuesta aceptar que mi relación de pareja no sea como al principio.",
    (
        "14. Me altero fácilmente cuando algo inesperado perturba mi vida"
        " cotidiana."
    ),
    "15. Los sentimientos de los demás no me preocupan.",
    (
        "16. Abandono fácilmente las tareas cuando me encuentro con ciertas"
        " dificultades."
    ),
    "17. Me pongo nervioso cuando alguien me halaga.",
    "18. Habitualmente compro cosas que no necesito sólo porque me apetece.",
    (
        "19. Me siento angustiado cuando en mi vida ocurre algo que no tengo"
        " previsto."
    ),
    (
        "20. Si presto algo y me lo devuelven estropeado, soy incapaz de decir"
        " nada."
    ),
    (
        "21. Tan pronto me siento lleno de vitalidad como profundamente"
        " cansado."
    ),
    "22. Cuando alguien me critica injustamente me defiendo dialogando.",
    (
        "23. Creo que las despedidas me resultan más difíciles que al resto de"
        " las personas."
    ),
    (
        "24. A veces me entusiasmo tanto con alguna idea nueva que no pienso en"
        " los inconvenientes que pueda tener."
    ),
    "25. Me siento incómodo cuando alguien se acerca demasiado.",
    "26. Tengo tendencia a enojarme cuando las cosas no me salen bien.",
    (
        "27. Las dificultades de otros países no nos incumben, es algo que"
        " deben solucionárselo ellos."
    ),
    "28. Soy una persona a la que los demás utilizan.",
    "29. Me es fácil conectar con la gente.",
    "30. No me preocupa ser rechazado por los demás.",
    "31. Me preocupa que los demás no me quieran.",
    "32. Cuando surge un problema prefiero que lo resuelva otro.",
    "33. Me cuesta mucho pedir favores.",
    (
        "34. Cuando estoy ocupado en algo acepto con tranquilidad cualquier"
        " interrupción."
    ),
    "35. A veces pienso que no valgo para nada.",
    "36. En general, me gusta la gente.",
    "37. Nunca bebo líquidos.",
    "38. Me encanta organizar fiestas con mis amigos.",
    "39. En alguna ocasión me he quedado con algo que no era de mi propiedad.",
    "40. No me cuesta trabajo asumir los cambios de mi cuerpo.",
    "41. Cuando estoy solo me siento triste.",
    (
        "42. Antes de tomar una decisión suelo tener en cuenta todas las"
        " posibilidades."
    ),
    (
        "43. Si mi hijo adolescente me propusiera algo excepcional, en principio"
        " estaría dispuesto a escucharle."
    ),
    (
        "44. Considero que tengo menos cualidades que el resto de las"
        " personas."
    ),
    "45. Necesito sentirme arropado por alguien.",
    "46. Es muy raro que algo o alguien me haga perder los estribos.",
    "47. Conecto fácilmente con los sentimientos de las personas.",
    "48. Me cuesta mucho desprenderme de los objetos de mi infancia.",
    "49. No me importa lo que piensen los demás sobre mis opiniones.",
    (
        "50. El que haya organizaciones que presten ayuda a otros países me"
        " parece un gasto innecesario."
    ),
    "51. Suelo reaccionar sin pensar mucho en lo que hago.",
    (
        "52. Ante situaciones conceptuales o peligrosas me altero menos que"
        " los demás."
    ),
    "53. No me suelo alterar por pequeñeces.",
    "54. Sufro cuando deseo tener o comprar algo que no puedo.",
    (
        "55. Solo me interesan aquellas cosas que están relacionadas con mi"
        " campo de interés."
    ),
    (
        "56. Si en un restaurante recibo un mal servicio hago la reclamación"
        " oportuna."
    ),
    "57. Suelo reconocer las cualidades positivas que tengo.",
    "58. No me cuesta comprometerme emocionalmente con otras personas.",
    "59. Acepto con naturalidad que alguien diga cosas positivas de mí.",
    "60. Me cuesta comprender otras religiones.",
    (
        "61. Si alguien me atrae encuentro la forma de establecer comunicación"
        " con él."
    ),
    "62. Hago las cosas sin pararme a pensar.",
    "63. Me cuesta mucho percibir las cualidades positivas que tengo.",
    "64. Suelo hablar sin pensar demasiado lo que digo.",
    (
        "65. Me siento mal cuando no tengo relaciones afectivas duraderas con"
        " otras personas."
    ),
    "66. Sé controlar mis sentimientos y no dejo que estos me desborden.",
    "67. No me importa lo que los demás piensen de mí.",
    "68. Me considero capaz de hacer las cosas tan bien como los demás.",
    "69. Ni en situaciones muy tensas me irrito.",
    "70. Me da igual que se mueran plantas o animales si yo no los he cuidado.",
    "71. Me incomoda ver llorar a una persona.",
    "72. Pienso detenidamente las cosas antes de hacerlas.",
    "73. Me enfado conmigo mismo cuando fallo en algo.",
    "74. Me asustan los cambios de la vida cotidiana.",
    "75. No me resulta fácil entablar conversación con desconocidos.",
    "76. Es imposible que me enfade con nadie.",
    "77. Me angustia que una relación afectiva importante se pueda romper.",
    "78. Me desanimo fácilmente ante los imprevistos.",
    "79. Comprendo fácilmente el punto de vista de los demás.",
    "80. Suelo decir siempre la verdad.",
    "81. Ante situaciones difíciles me mantengo sereno.",
    "82. Si un amigo/a me pide ayuda dejo lo que estoy haciendo y acudo.",
    "83. Me adapto con facilidad a los cambios de planes.",
    "84. Intento ponerme en el lugar de las personas que sufren.",
    "85. Si cometo un error prefiero admitirlo que buscar excusas.",
    "86. Siento que los demás valoran mi trabajo y mi esfuerzo.",
    "87. Me cuesta superar la pérdida de seres queridos.",
    "88. No me molesta que me lleven la contraria.",
    "89. Pienso bien las consecuencias antes de actuar.",
    "90. Me resulta fácil expresar mis sentimientos a las personas que quiero.",
    "91. Acepto las normas aunque a veces no esté de acuerdo.",
    "92. Tengo confianza en mis capacidades para solucionar problemas.",
    "93. Evito las discusiones innecesarias.",
    "94. Me resulta difícil pedir perdón cuando me equivoco.",
    "95. Muestro paciencia ante las dificultades de los demás.",
    "96. Me esfuerzo por entender las opiniones distintas a la mía.",
    "97. Respeto las decisiones de los demás aunque no las comparta.",
    "98. Me siento seguro al tomar decisiones importantes.",
    "99. Mantengo la calma aunque las cosas salgan mal.",
    "100. Sé escuchar atentamente cuando alguien me habla.",
    "101. Me cuesta controlar el malestar cuando me contradicen.",
    "102. Intento resolver los conflictos buscando el beneficio de todos.",
    "103. Siento satisfacción cuando ayudo a los demás.",
    "104. Acepto mis limitaciones personales sin frustrarme.",
    "105. Me cuesta adaptarme a nuevas situaciones laborales o personales.",
    (
        "106. Trato con respeto a todas las personas independientemente de su"
        " condición."
    ),
    "107. Controlo mis impulsos cuando me siento molesto.",
    "108. Sé decir que no sin sentir culpa.",
    "109. Me preocupa el bienestar de los niños y personas vulnerables.",
    "110. Acepto las críticas si son constructivas.",
    "111. Me resulta fácil ponerme en el lugar de los niños.",
    "112. Sé mantener los límites con firmeza y afecto.",
    "113. No me dejo llevar por la ira ante las provocaciones.",
    "114. Me considero una persona tolerante.",
    "115. Sé manejar el estrés en momentos de crisis.",
    "116. Acepto a las personas tal como son.",
    "117. Me cuesta pedir ayuda cuando me siento desbordado.",
    "118. Expreso lo que pienso con claridad y respeto.",
    "119. Me preocupa la injusticia social.",
    "120. Mantengo el compromiso asumido a pesar de las dificultades.",
    "121. Me resulta fácil establecer un vínculo de confianza.",
    "122. Admito mis equivocaciones frente a los niños o subordinados.",
    "123. Mantengo una actitud positiva ante la vida.",
    "124. Sé reaccionar con flexibilidad ante imprevistos graves.",
    "125. Entiendo la importancia del afecto en la educación.",
    "126. Evito el uso de la violencia verbal o física en cualquier circunstancia.",
    "127. Me siento capaz de cuidar y proteger a otros.",
    "128. Sé perdonar las faltas de los demás.",
    "129. Me comunico con claridad y paciencia.",
    "130. Acepto que los demás tengan prioridades distintas a las mías.",
    "131. Mantengo el autocontrol cuando me siento presionado.",
    (
        "132. Me involucro de forma activa en la resolución de problemas"
        " comunitarios."
    ),
    "133. Reconozco el esfuerzo de los demás y los felicito.",
    "134. Sé gestionar mis frustraciones sin desquitarme con otros.",
    (
        "135. Muestro empatía hacia las personas que están pasando por momentos"
        " tristes."
    ),
    "136. Acepto los cambios en las rutinas con naturalidad.",
    (
        "137. Sé poner los intereses del grupo o familia por encima de los mías"
        " cuando es necesario."
    ),
    "138. Mantengo la serenidad durante discusiones acaloradas.",
    "139. Me resulta fácil expresar ternura.",
    "140. No me guardo rencor por ofensas pasadas.",
    "141. Busco el diálogo antes de tomar medidas drásticas.",
    "142. Muestro flexibilidad mental ante posturas opuestas.",
    "143. Me siento preparado para asumir responsabilidades de cuidado.",
    "144. Respeto el ritmo de aprendizaje o desarrollo de cada persona.",
    "145. Sé transmitir seguridad y tranquilidad a quienes me rodean.",
    "146. Acepto con calma las equivocaciones ajenas.",
    "147. Mantengo el entusiasmo a pesar de los obstáculos.",
    "148. Me adapto sin dificultad a entornos nuevos.",
    "149. Valoro la honestidad por encima de todo.",
    "150. Sé pedir disculpas si he respondido de forma inadecuada.",
    "151. Comprendo el impacto de mis acciones en los demás.",
    "152. Muestro disponibilidad para escuchar las necesidades ajenas.",
    "153. No me desespero cuando las respuestas no son inmediatas.",
    "154. Acepto la diversidad de pensamiento en mi entorno.",
    "155. Controlo mis temores ante situaciones desconocidas.",
    "156. Muestro afecto sincero hacia los niños.",
    "157. Sé poner límites claros sin perder la calma.",
    "158. Respeto el tiempo de los demás.",
    "159. Acepto con madurez las pérdidas o fracasos.",
    "160. Busco soluciones constructivas ante los dilemas cotidianos.",
    "161. Me resulta sencillo ponerme en el lugar de alguien que sufre.",
    "162. Mantengo la coherencia entre lo que digo y hago.",
    (
        "163. Sé mantener la distancia adecuada sin ser distante ni"
        " invasivo."
    ),
    "164. Me muestro accesible ante las demandas de ayuda.",
    "165. Sé mantener la paz interior en momentos de tensión.",
    "166. Acepto las reglas de convivencia con agrado.",
    "167. Me siento capaz de sostener emocionalmente a otro.",
    "168. Muestro paciencia ante las rabieta o berrinches infantiles.",
    "169. Respeto el intimidad y el espacio ajeno.",
    "170. Mantengo una actitud de colaboración constante.",
    (
        "171. Sé adaptarme a las exigencias del entorno sin perder mi"
        " identidad."
    ),
    "172. Acepto que las cosas no siempre salgan según lo previsto.",
    "173. Muestro un interés sincero por las emociones de las personas.",
    "174. Sé manejar la presión de tiempo sin perder los nervios.",
    "175. Me comunico de manera asertiva y pausada.",
    "176. Acepto las diferencias individuales con agrado.",
    "177. Mantengo el equilibrio emocional frente al conflicto.",
    "178. Muestro responsabilidad en el cuidado de terceros.",
    "179. Sé motivar a los demás en momentos difíciles.",
    "180. Respeto la autoridad legítima.",
    "181. Acepto mis propios errores sin buscar culpables.",
    "182. Sé escuchar sin interrumpir.",
    "183. Muestro disposición para el trabajo cooperativo.",
    "184. Mantengo la objetividad en las evaluaciones personales.",
    "185. Acepto con gratitud la ayuda que me brindan.",
    "186. Sé brindar protección afectiva y física.",
    "187. Muestro comprensión ante las debilidades ajenas.",
    "188. Mantengo la firmeza en mis valores fundamentales.",
    "189. Sé dar respuestas serenas en situaciones críticas.",
]

OPCIONES_CUIDA = {
    1: "1 - Completamente en desacuerdo",
    2: "2 - En desacuerdo",
    3: "3 - De acuerdo",
    4: "4 - Completamente de acuerdo",
}

ITEMS_STAI = [
    "1. Me siento calmado/a (Ansiedad Estado)",
    "2. Me siento seguro/a (Ansiedad Estado)",
    "3. Estoy tenso/a (Ansiedad Estado)",
    "4. Me siento contrariado/a (Ansiedad Estado)",
    "5. Me siento cómodo/a (Ansiedad Estado)",
    "6. Me siento alterado/a (Ansiedad Estado)",
    "7. Estoy preocupado/a por posibles desgracias (Ansiedad Estado)",
    "8. Me siento descansado/a (Ansiedad Estado)",
    "9. Me siento angustiado/a (Ansiedad Estado)",
    "10. Me siento confortable (Ansiedad Estado)",
    "11. Tengo confianza en mí mismo/a (Ansiedad Estado)",
    "12. Me siento nervioso/a (Ansiedad Estado)",
    "13. Estoy desasosegado/a (Ansiedad Estado)",
    "14. Me siento muy atado/a (Ansiedad Estado)",
    "15. Me siento relajado/a (Ansiedad Estado)",
    "16. Me siento satisfecho/a (Ansiedad Estado)",
    "17. Estoy preocupado/a (Ansiedad Estado)",
    "18. Me siento aturdido/a o sobreexcitado/a (Ansiedad Estado)",
    "19. Me siento alegre (Ansiedad Estado)",
    "20. Me siento de buen humor (Ansiedad Estado)",
    "21. Me siento bien (Ansiedad Rasgo)",
    "22. Me canso rápidamente (Ansiedad Rasgo)",
    "23. Siento ganas de llorar (Ansiedad Rasgo)",
    "24. Desearía ser tan feliz como otros parecen serlo (Ansiedad Rasgo)",
    "25. Pierdo oportunidades por no decidirme pronto (Ansiedad Rasgo)",
    "26. Me siento descansado/a (Ansiedad Rasgo)",
    "27. Soy una persona tranquila, serena y sosegada (Ansiedad Rasgo)",
    (
        "28. Siento que las dificultades se me acumulan al punto de no poder"
        " superarlas (Ansiedad Rasgo)"
    ),
    (
        "29. Me preocupo demasiado por cosas que no tienen importancia"
        " (Ansiedad Rasgo)"
    ),
    "30. Soy feliz (Ansiedad Rasgo)",
    "31. Siento tendencia a tomar las cosas muy a pecho (Ansiedad Rasgo)",
    "32. Me falta confianza en mí mismo/a (Ansiedad Rasgo)",
    "33. Me siento seguro/a (Ansiedad Rasgo)",
    "34. Evito enfrentarme a las crisis o dificultades (Ansiedad Rasgo)",
    "35. Me siento melancólico/a (Ansiedad Rasgo)",
    "36. Me siento satisfecho/a (Ansiedad Rasgo)",
    (
        "37. Algunas ideas poco importantes me rondan la cabeza y me molestan"
        " (Ansiedad Rasgo)"
    ),
    (
        "38. Me afectan tanto los desengaños que no puedo olvidarlos (Ansiedad"
        " Rasgo)"
    ),
    "39. Soy una persona estable (Ansiedad Rasgo)",
    (
        "40. Cuando pienso en mis asuntos actuales me pongo tenso/a (Ansiedad"
        " Rasgo)"
    ),
]

OPCIONES_STAI = {
    0: "0 - Nada / Casi nunca",
    1: "1 - Algo / A veces",
    2: "2 - Bastante / A menudo",
    3: "3 - Mucho / Casi siempre",
}

ITEMS_BDI = [
    {
        "titulo": "1. Tristeza",
        "opciones": [
            "0 - No me siento triste.",
            "1 - Me siento triste gran parte del tiempo.",
            "2 - Estoy triste todo el tiempo.",
            (
                "3 - Estoy tan triste o soy tan desdichado que no puedo"
                " soportarlo."
            ),
        ],
    },
    {
        "titulo": "2. Pesimismo",
        "opciones": [
            "0 - No me siento desanimado/a respecto al futuro.",
            "1 - Me siento más desanimado/a respecto al futuro que antes.",
            "2 - No espero que las cosas mejoren para mí.",
            (
                "3 - Siento que el futuro es desesperanzador y que las cosas"
                " solo empeorarán."
            ),
        ],
    },
    {
        "titulo": "3. Fracaso",
        "opciones": [
            "0 - No me siento como un/a fracasado/a.",
            "1 - He fracasado más de lo que debería.",
            "2 - Cuando miro hacia atrás, veo muchos fracasos.",
            "3 - Siento que como persona soy un fracaso total.",
        ],
    },
    {
        "titulo": "4. Pérdida de placer",
        "opciones": [
            "0 - Obtengo tanto placer como siempre de las cosas que me gustan.",
            "1 - No disfruto de las cosas tanto como antes.",
            "2 - Obtengo muy poco placer de las cosas que antes disfrutaba.",
            "3 - No puedo obtener ningún placer de las cosas que antes disfrutaba.",
        ],
    },
    {
        "titulo": "5. Sentimientos de culpa",
        "opciones": [
            "0 - No me siento particularmente culpable.",
            (
                "1 - Me siento culpable respecto a varias cosas que he hecho o"
                " debería haber hecho."
            ),
            "2 - Me siento culpable bastante a menudo.",
            "3 - Me siento culpable todo el tiempo.",
        ],
    },
    {
        "titulo": "6. Sentimientos de castigo",
        "opciones": [
            "0 - No siento que esté siendo castigado/a.",
            "1 - Siento que tal vez pueda ser castigado/a.",
            "2 - Espero ser castigado/a.",
            "3 - Siento que estoy siendo castigado/a.",
        ],
    },
    {
        "titulo": "7. Disconformidad con uno mismo",
        "opciones": [
            "0 - Siento lo mismo que antes sobre mí mismo/a.",
            "1 - He perdido la confianza en mí mismo/a.",
            "2 - Estoy decepcionado/a de mí mismo/a.",
            "3 - No me gusto en absoluto.",
        ],
    },
    {
        "titulo": "8. Autocrítica",
        "opciones": [
            "0 - No me critico ni me culpo más de lo habitual.",
            "1 - Estoy más crítico/a conmigo mismo/a de lo que solía estar.",
            "2 - Me critico a mí mismo/a por todos los errores.",
            "3 - Me culpo a mí mismo/a por todo lo malo que sucede.",
        ],
    },
    {
        "titulo": "9. Pensamientos o deseos suicidas",
        "opciones": [
            "0 - No tengo ningún pensamiento de matarme.",
            "1 - Tengo pensamientos de matarme, pero no los llevaría a cabo.",
            "2 - Me gustaría matarme.",
            "3 - Me mataría si tuviera la oportunidad.",
        ],
    },
    {
        "titulo": "10. Llanto",
        "opciones": [
            "0 - No lloro más de lo que solía hacerlo.",
            "1 - Lloro más de lo que solía hacerlo.",
            "2 - Lloro por cualquier pequeñez.",
            "3 - Siento ganas de llorar pero no puedo.",
        ],
    },
    {
        "titulo": "11. Agitación",
        "opciones": [
            "0 - No me siento más inquieto/a o agitado/a que de costumbre.",
            "1 - Me siento más inquieto/a o agitado/a que de costumbre.",
            (
                "2 - Estoy tan inquieto/a o agitado/a que me cuesta quedarme"
                " quieto/a."
            ),
            (
                "3 - Estoy tan inquieto/a o agitado/a que tengo que estar en"
                " constante movimiento."
            ),
        ],
    },
    {
        "titulo": "12. Pérdida de interés",
        "opciones": [
            "0 - No he perdido el interés en otras personas o actividades.",
            "1 - Estoy menos interesado/a en otras personas o cosas que antes.",
            "2 - He perdido casi todo el interés en otras personas o cosas.",
            "3 - Me resulta difícil interesarme por algo.",
        ],
    },
    {
        "titulo": "13. Indecisión",
        "opciones": [
            "0 - Tomo decisiones tan bien como siempre.",
            "1 - Me resulta más difícil tomar decisiones que de costumbre.",
            (
                "2 - Tengo mucha más dificultad para tomar decisiones que"
                " antes."
            ),
            "3 - Tengo problemas para tomar cualquier decisión.",
        ],
    },
    {
        "titulo": "14. Inutilidad",
        "opciones": [
            "0 - No me siento inútil.",
            "1 - No me considero tan valioso/a e útil como solía ser.",
            "2 - Me siento más inútil en comparación con otras personas.",
            "3 - Me siento totalmente inútil.",
        ],
    },
    {
        "titulo": "15. Pérdida de energía",
        "opciones": [
            "0 - Tengo tanta energía como siempre.",
            "1 - Tengo menos energía de la que solía tener.",
            "2 - No tengo suficiente energía para hacer casi nada.",
            "3 - No tengo energía para hacer nada.",
        ],
    },
    {
        "titulo": "16. Cambios en el patrón de sueño",
        "opciones": [
            "0 - No he experimentado ningún cambio en mi patrón de sueño.",
            "1 - Duermo algo más o algo menos que de costumbre.",
            "2 - Duermo mucho más o mucho menos que de costumbre.",
            (
                "3 - Duermo la mayor parte del tiempo o me despierto 1-2 horas"
                " antes y no puedo volver a dormirme."
            ),
        ],
    },
    {
        "titulo": "17. Irritabilidad",
        "opciones": [
            "0 - No estoy más irritable de lo habitual.",
            "1 - Estoy más irritable de lo habitual.",
            "2 - Estoy mucho más irritable de lo habitual.",
            "3 - Estoy irritable todo el tiempo.",
        ],
    },
    {
        "titulo": "18. Cambios en el apetito",
        "opciones": [
            "0 - No he experimentado ningún cambio en mi apetito.",
            "1 - Mi apetito es algo menor o mayor que de costumbre.",
            "2 - Mi apetito es mucho menor o mayor que de costumbre.",
            (
                "3 - No tengo apetito en absoluto o tengo ansias de comer todo"
                " el tiempo."
            ),
        ],
    },
    {
        "titulo": "19. Dificultad de concentración",
        "opciones": [
            "0 - Puedo concentrarme tan bien como siempre.",
            "1 - No puedo concentrarme tan bien como habitualmente.",
            (
                "2 - Me cuesta mantener la concentración en cualquier cosa por"
                " mucho tiempo."
            ),
            "3 - Encuentro que no puedo concentrarme en nada.",
        ],
    },
    {
        "titulo": "20. Cansancio o fatiga",
        "opciones": [
            "0 - No estoy más cansado/a o fatigado/a que de costumbre.",
            "1 - Me canso o fatigo más fácilmente que de costumbre.",
            (
                "2 - Estoy demasiado cansado/a o fatigado/a para hacer muchas de"
                " las cosas que solía hacer."
            ),
            (
                "3 - Estoy demasiado cansado/a o fatigado/a para hacer la"
                " mayoría de las cosas que solía hacer."
            ),
        ],
    },
    {
        "titulo": "21. Pérdida de interés en el sexo",
        "opciones": [
            "0 - No he notado ningún cambio reciente en mi interés por el sexo.",
            "1 - Estoy menos interesado/a en el sexo de lo que solía estar.",
            "2 - Estoy mucho menos interesado/a en el sexo ahora.",
            "3 - He perdido el interés en el sexo por completo.",
        ],
    },
]

ITEMS_PAI = [
    "1. Mis amigos están disponibles cuando los necesito.",
    "2. Tengo algunos conflictos internos que me causan problemas.",
    "3. Mi salud ha limitado algunas de mis actividades.",
    (
        "4. En algunas ocasiones siento tanta tensión que me cuesta mucho"
        " soportarlo."
    ),
    (
        "5. A veces necesito hacer las cosas de una cierta forma para evitar"
        " ponerme nervioso."
    ),
    "6. Estoy triste gran parte del tiempo sin que haya una razón para ello.",
    (
        "7. Con frecuencia pienso y hablo tan deprisa que los demás no pueden"
        " seguir mi pensamiento."
    ),
    "8. La mayor parte de la gente que conozco es digna de confianza.",
    "9. De vez en cuando pierdo completamente la memoria.",
    "10. Tengo algunas ideas que los demás consideran extrañas.",
    "11. He dañado intencionadamente algunas pertenencias de otras personas.",
    "12. Mi salud es muy buena para mi edad.",
    "13. Soy una persona muy sociable.",
    "14. Tengo cambios de humor repentinos.",
    "15. A veces me siento culpable por la cantidad de alcohol que bebo.",
    (
        "16. Me encuentro a gusto en las situaciones en las que tengo que"
        " dirigir a otros."
    ),
    "17. A menudo cambio la imagen y la idea que tengo sobre mí.",
    "18. Tengo bastante mal carácter.",
    "19. He tenido algunas relaciones tormentosas.",
    "20. En ciertas ocasiones me gustaría estar muerto.",
    "21. La gente tiene miedo de mi temperamento.",
    "22. A veces tomo drogas para sentirme mejor.",
    "23. He probado casi todos los tipos de drogas.",
    "24. A veces incluso las cosas pequeñas me preocupan demasiado.",
    "25. Suelo tener dificultad para concentrarme a causa de mis nervios.",
    (
        "26. Con frecuencia tengo miedo de 'meter la pata' y decir algo"
        " inconveniente."
    ),
    "27. Siento que he decepcionado a todo el mundo.",
    "28. Tengo muchas ideas brillantes.",
    "29. Hay personas que quieren hacerme daño.",
    "30. Me parece que no me relaciono bien con la gente.",
    (
        "31. He pedido dinero prestado a sabiendas de que no podría"
        " devolverlo."
    ),
    "32. La mayor parte del tiempo no me encuentro bien.",
    "33. Con frecuencia me siento inquieto.",
    "34. Sigo reviviendo algo horrible que me ocurrió.",
    "35. Casi no tengo energía.",
    (
        "36. Me enfado cuando otras personas son demasiado lentas para entender"
        " mis ideas."
    ),
    "37. La gente suele tratarme bastante bien.",
    "38. Mis pensamientos se han hecho bastante confusos.",
    "39. Disfruto haciendo cosas peligrosas.",
    "40. Mi poeta favorito es Ruperto Miralles.",
    "41. La mayor parte de las personas de mi entorno están cuando las necesito.",
    "42. Necesito hacer algunos cambios importantes en mi vida.",
    (
        "43. He tenido algunas enfermedades que los médicos no han sido"
        " capaces de explicar."
    ),
    "44. Mi nerviosismo me impide hacer algunas cosas bien.",
    "45. Tengo ciertos impulsos que lucho por controlar.",
    "46. He olvidado lo que es sentirse feliz.",
    (
        "47. Asumo tantos compromisos que luego no soy capaz de"
        " cumplirlos."
    ),
    (
        "48. Debo estar alerta ante la posibilidad de que algunas personas no"
        " sean leales."
    ),
    "49. No tengo casi ningún buen recuerdo de mi infancia.",
    "50. A veces otras personas meten ideas en mi cabeza.",
    "51. He realizado cosas que no eran completamente legales.",
    "52. Mis problemas de salud son muy complicados.",
    "53. Me resulta fácil hacer nuevos amigos.",
    "54. Experimento estados de ánimo muy intensos.",
    (
        "55. Tengo algunas dificultades para controlar la cantidad de alcohol"
        " que bebo."
    ),
    "56. Suelo actuar como un líder de forma natural.",
    "57. A veces tengo una intensa sensación de vacío interior.",
    "58. Nunca tengo problemas por culpa de mi temperamento.",
    "59. Quiero que algunas personas sepan que me han hecho mucho daño.",
    "60. He pensado en algunas formas de quitarme la vida.",
    "61. A veces exploto y pierdo completamente el control sobre mí.",
    "62. Algunas personas me han dicho que tengo problemas con las drogas.",
    "63. El consumo de drogas me ha producido algunos problemas de salud.",
    "64. No acepto bien las críticas.",
    (
        "65. Con frecuencia me resulta difícil divertirme porque todo me"
        " preocupa."
    ),
    "66. Tengo temores excesivamente grandes.",
    "67. A veces pienso que no valgo nada.",
    (
        "68. Tengo muchas cualidades interesantes de las que otras personas"
        " carecen."
    ),
    "69. Algunas personas hacen cosas para que yo quede mal.",
    "70. Tengo muy poco que decir a otras personas.",
    "71. Me aprovecharía de los demás si lo tuviera fácil.",
    "72. Tengo muchos dolores.",
    (
        "73. Algunas veces me preocupo tanto que me parece que voy a"
        " desmayarme."
    ),
    (
        "74. Con frecuencia me vienen recuerdos del pasado que me provocan"
        " malestar."
    ),
    "75. Concilio fácilmente el sueño.",
    "76. No tengo paciencia con la gente que intenta frenarme.",
    (
        "77. Creo que en mi vida he tenido tanta suerte como la mayor parte de"
        " la gente."
    ),
    "78. Algunas veces mezclo unos pensamientos con otros.",
    "79. Hago muchas cosas peligrosas sólo por la emoción que me producen.",
    (
        "80. A veces recibo por correo anuncios que no me interesan en"
        " absoluto."
    ),
    "81. Cuando tengo problemas cuento con personas con las que puedo hablar.",
    "82. Tengo que cambiar en algunos aspectos, aunque me cueste mucho.",
    (
        "83. Alguna parte de mi cuerpo se ha quedado insensible en ocasiones,"
        " sin saber por qué."
    ),
    "84. En algunas ocasiones tengo miedo sin que haya motivos para ello.",
    "85. Me incomoda que las cosas no estén en su sitio.",
    "86. Cualquier cosa me supone un gran esfuerzo.",
    (
        "87. Mis amigos no son capaces de seguir todas mis actividades"
        " sociales."
    ),
    "88. La mayor parte de la gente tiene buenas intenciones.",
    "89. Mi destino ha sido ser infeliz desde el día en que nací.",
    (
        "90. A veces parece que mis pensamientos se producen en voz alta y que"
        " los demás pueden oírlos."
    ),
    (
        "91. He dicho muchas mentiras para librarme de situaciones"
        " comprometidas."
    ),
    "92. Me cuesta mucho hacer las cosas por los problemas de salud que tengo.",
    "93. Me gusta conocer a nuevas personas.",
    "94. A veces me meto en problemas porque actúo de forma muy impulsiva.",
    "95. Algunas personas cercanas piensan que bebo demasiado.",
    "96. Se me dan bien los trabajos en los que hay que dirigir a otros.",
    "97. Me preocupa mucho que otras personas puedan abandonarme.",
    (
        "98. Cuando estoy conduciendo y me indigno con otros conductores hago"
        " que se den cuenta de ello."
    ),
    "99. Algunas personas muy próximas me han abandonado.",
    "100. He hecho planes para matarme.",
    "101. Cuando me enfurezco es muy difícil calmarme.",
    "102. He tenido problemas económicos por el consumo de drogas.",
    "103. Soy incapaz de controlar mi consumo de drogas.",
    "104. A veces me quejo demasiado.",
    (
        "105. Con frecuencia siento tal preocupación y nerviosismo que casi no"
        " puedo soportarlo."
    ),
    (
        "106. Cuando tengo que hacer algo delante de otras personas siento"
        " muchos nervios."
    ),
    "107. Me siento sin fuerzas para continuar.",
    "108. Tengo planes que me convertirán algún día en una persona famosa.",
    "109. Las personas que me rodean son leales conmigo.",
    "110. Soy una persona solitaria.",
    "111. Haría cualquier cosa si me pagasen lo suficiente.",
    "112. Tengo buena salud.",
    (
        "113. A veces siento mareos cuando he estado sometido a una presión"
        " fuerte."
    ),
    (
        "114. El recuerdo de una mala experiencia me ha afectado durante mucho"
        " tiempo."
    ),
    "115. Es raro que tenga algunas dificultades para dormir.",
    "116. A veces me irrito porque otras personas no comprenden mis planes.",
    "117. He dado mucho pero es poco lo que he recibido a cambio.",
    "118. Algunas veces me cuesta separar unos pensamientos de otros.",
    "119. A veces me comporto de forma desenfrenada e insensata.",
    "120. El deporte que más me gusta ver por televisión es el salto de altura.",
    "121. Las personas que conozco se preocupan por mí.",
    "122. Necesito ayuda para afrontar los problemas importantes.",
    (
        "123. En alguna ocasión mis piernas estaban tan débiles que no podía"
        " caminar."
    ),
    (
        "124. A menudo tengo la sensación de que está a punto de ocurrir algo"
        " horrible."
    ),
    "125. Soy capaz de descansar aunque mi casa esté desordenada.",
    "126. Parece que nada es capaz de proporcionarme placer.",
    "127. En ocasiones mis pensamientos se mueven a una velocidad excesiva.",
    "128. La gente suele ocultar sus verdaderas intenciones.",
    "129. Tengo problemas psicológicos graves que comenzaron de forma repentina.",
    "130. Hay personas que intentan controlar mis pensamientos.",
    "131. Nunca he tenido conflictos con la ley.",
    (
        "132. Parece que mis problemas de salud son siempre difíciles de"
        " tratar."
    ),
    "133. Soy una persona acogedora.",
    "134. A veces no puedo contener mi rabia.",
    (
        "135. Mi costumbre de beber me ha producido algunos problemas en las"
        " relaciones con los demás."
    ),
    "136. Me cuesta mucho defenderme sin ayuda.",
    "137. A menudo me pregunto lo que debería hacer con mi vida.",
    (
        "138. Sería capaz de gritar a otros con tal de que queden claros mis"
        " argumentos."
    ),
    "139. Cuando estoy muy enfadado suelo hacer cosas para hacerme daño.",
    "140. En los últimos tiempos he estado pensando en el suicidio.",
    "141. A veces rompo cosas cuando estoy muy furioso.",
    "142. Nunca consumo drogas ilegales.",
    "143. Me perjudica mi comportamiento excesivamente impulsivo.",
    "144. A veces soy demasiado impaciente.",
    "145. Mis amigos dicen que me preocupo demasiado.",
    "146. Rara vez siento miedo.",
    "147. Por más que lo intente, nada me sale bien.",
    "148. Creo que tengo las respuestas a algunas preguntas importantes.",
    "149. Algunas personas tratan de impedir que yo pueda progresar.",
    "150. Hay pocas personas a las que sienta cercanas.",
    "151. Pienso en mí ante todo y dejo que los demás cuiden de sí mismos.",
    "152. Rara vez me quejo de mi estado de salud.",
    "153. A veces me cuesta respirar cuando me someto a mucha tensión.",
    (
        "154. Parece que no puedo librarme de ciertos acontecimientos del"
        " pasado."
    ),
    "155. He estado moviéndome con más lentitud de lo normal.",
    (
        "156. Tengo planes importantes y me molesta mucho que otras personas"
        " intenten meterse en medio."
    ),
    (
        "157. Muchas personas no son capaces de apreciar lo que he hecho por"
        " ellas."
    ),
    "158. A veces parece que alguien está bloqueando mis pensamientos.",
    "159. Me gusta conducir muy deprisa.",
    "160. La mayor parte de la gente está deseando ir al dentista.",
    "161. La gente no comprende lo mucho que sufro.",
    "162. Tengo muchos problemas económicos.",
    "163. Recientemente se han producido muchos cambios en mi vida.",
    "164. En mi casa hay poca estabilidad.",
    "165. Las cosas no van bien en mi familia.",
    "166. He perdido el interés por cosas que antes me gustaban.",
    "167. Últimamente tengo menos necesidad de dormir de la habitual.",
    "168. Generalmente doy por supuesto que la gente dice la verdad.",
    "169. Paso la mayor parte del tiempo en soledad.",
    "170. He oído voces que nadie más es capaz de oír.",
    (
        "171. Me gusta hacer cosas sólo para comprobar si puedo salir impune"
        " de ellas."
    ),
    (
        "172. He tenido únicamente los problemas de salud que la mayoría de la"
        " gente tiene."
    ),
    (
        "173. Necesito tiempo para sentirme en confianza con personas que no"
        " conozco."
    ),
    "174. Siempre he sido una persona bastante feliz.",
    "175. La bebida me ayuda a sobrellevar ciertas situaciones sociales.",
    "176. Soy el tipo de persona que se hace cargo de las cosas.",
    (
        "177. No puedo soportar separarme de las personas que son muy cercanas"
        " a mí."
    ),
    "178. Nunca pierdo el control por estar demasiado furioso.",
    (
        "179. He cometido algunos errores graves en relación con las personas"
        " que he elegido como amigas."
    ),
    "180. Durante mucho tiempo he estado pensando en el suicidio.",
    "181. He amenazado a otras personas con hacerlas daño.",
    "182. He utilizado medicamentos para animarme.",
    "183. Suelo tener pocos cambios de humor.",
    "184. A veces intento evitar a las personas que me disgustan.",
    (
        "185. Mi preocupación por las cosas es similar a la de la mayoría de"
        " las personas."
    ),
    "186. No me asusta conducir por autopistas.",
    "187. Me parece que me cuesta mucho concentrarme.",
    "188. He tenido algunos éxitos destacados.",
    "189. Algunas personas cambian sus planes para molestarme.",
    "190. Disfruto con la compañía de otras personas.",
    "191. No me gusta sentirme ligado a otra persona.",
    "192. Tengo problemas de espalda.",
    "193. Soy capaz de relajarme con facilidad.",
    (
        "194. He tenido algunas experiencias terribles que hacen que me sienta"
        " culpable."
    ),
    (
        "195. Con frecuencia me despierto muy temprano por la mañana y luego"
        " no puedo volver a dormirme."
    ),
    "196. Puedo ser muy exigente cuando quiero que las cosas se hagan deprisa.",
    "197. Generalmente se ha reconocido lo que he hecho.",
    "198. Mi mente tiende a saltar rápidamente de unas cosas a otras.",
    "199. La idea de una vida tranquila y ordenada nunca me ha interesado.",
    "200. Mis aficiones favoritas son el tiro con arco y la filatelia.",
    "201. Me gusta estar con mi familia.",
    "202. Me gusta cómo soy.",
    "203. En ciertas ocasiones he perdido la sensibilidad en las manos.",
    "204. Raras veces siento tensión o ansiedad.",
    "205. Normalmente me doy cuenta de cuando algo tiene muchos gérmenes.",
    "206. No me interesa la vida.",
    (
        "207. Tengo la sensación de que necesito estar en constante actividad,"
        " sin descansar."
    ),
    "208. La gente piensa que soy demasiado suspicaz.",
    "209. A veces no puedo recordar quién soy.",
    "210. Otras personas pueden leer mis pensamientos.",
    (
        "211. Nunca me expulsaron de la escuela durante my niñez, ni siquiera"
        " temporalmente."
    ),
    "212. He tenido algunas enfermedades o molestias bastante raras.",
    "213. Se necesita tiempo para que otras personas lleguen a conocerme.",
    (
        "214. En algunas ocasiones me he enfurecido tanto que era incapaz de"
        " manifestar toda la ira que sentía."
    ),
    "215. En ocasiones he tenido que dejar la bebida.",
    "216. Prefiero que sean otros los que toman las decisiones.",
    "217. Normalmente no me aburro.",
    "218. Siempre que puedo evito las discusiones.",
    "219. Cuando tengo un amigo o amiga, lo es para mucho tiempo.",
    "220. La muerte sería un alivio.",
    "221. La gente piensa que soy una persona agresiva.",
    "222. Nunca consumo drogas para ayudarme a enfrentarme al mundo.",
    "223. Rara vez me siento una persona solitaria.",
    "224. A veces dejo las cosas para el último momento.",
    "225. Generalmente me preocupo por las cosas más de lo que debería.",
    "226. No me asustan las alturas.",
    "227. Creo que en el futuro me van a ocurrir cosas favorables.",
    "228. Creo que podría ser un buen cómico.",
    "229. Es muy raro que la gente me trate mal a propósito.",
    "230. Siempre que puedo me gusta estar con otras personas.",
    "231. No me gusta mantener una relación durante mucho tiempo.",
    "232. Tengo problemas de estómago.",
    "233. A veces noto que mi corazón late muy fuerte.",
    "234. Sigo teniendo pesadillas sobre el pasado.",
    "235. Tengo buen apetito.",
    (
        "236. Me molesta mucho si alguna persona trata de impedir que cumpla"
        " mis objetivos."
    ),
    "237. La gente que ha tenido éxito generalmente lo ha merecido.",
    "238. A veces me parece que me han robado los pensamientos.",
    "239. Cuando me canso de un sitio inmediatamente me voy a otro.",
    "240. No me gusta comprar cosas que me parecen excesivamente caras.",
    "241. En mi familia discutimos más que hablamos.",
    "242. Muchos de mis problemas son consecuencia de mi actitud.",
    "243. He tenido experiencias de visión doble o de visión borrosa.",
    "244. Me sobresalto con facilidad.",
    "245. Los demás consideran que presto mucha atención a los detalles.",
    "246. En los últimos tiempos he sentido feliz habitualmente.",
    "247. Últimamente tengo menos necesidad de dormir de la habitual.",
    "248. Generalmente las cosas no son lo que aparentan a primera vista.",
    "249. A veces veo sólo en blanco y negro.",
    "250. Tengo un sexto sentido que me avisa de las cosas que van a ocurrir.",
    "251. Generalmente me portaba bien cuando iba al colegio.",
    "252. He ido muchas veces al médico en mi vida.",
    "253. Intento acoger a las personas que parecen estar solas.",
    "254. A veces tomo una copa de una bebida alcohólica nada más levantarme.",
    "255. La bebida me ha causado algunos problemas en casa.",
    "256. Digo siempre lo que pienso.",
    "257. Suelo hacer lo que otras personas quieren que haga.",
    "258. A veces puedo ser una persona muy violenta.",
    "259. Es muy difícil hacer que me enfade.",
    "260. He estado pensando en lo qué podría decir en una carta de suicidio.",
    "261. No tengo motivos para seguir viviendo.",
    "262. Nunca he tenido problemas en el trabajo por causa de las drogas.",
    "263. Gasto el dinero con demasiada facilidad.",
    "264. A veces hago promesas que no puedo cumplir.",
    "265. A veces me pongo tan nervioso que me parece que voy a morir.",
    "266. Evito montarme en aviones.",
    "267. Tengo cosas importantes que aportar.",
    (
        "268. Últimamente confío tanto en mí que creo que puedo conseguir lo"
        " que me proponga."
    ),
    "269. La gente me tiene manía.",
    "270. Hago amigos con facilidad.",
    "271. Siempre tengo algo que decir u opinar sobre cualquier cosa.",
    (
        "272. Me duele la cabeza con más frecuencia que a la mayor parte de la"
        " gente."
    ),
    "273. Me sudan las manos con frecuencia.",
    (
        "274. Tuve una experiencia muy mala que me ha hecho perder el interés"
        " por algunas cosas con las que antes disfrutaba."
    ),
    "275. A menudo me despierto a mitad de la noche.",
    "276. A veces estoy muy suspicaz y me enfado con facilidad.",
    "277. No soy una persona que suela guardar rencor.",
    "278. Los pensamientos desaparecen rápidamente de mi mente.",
    "279. Nunca tomo riesgos si puedo evitarlo.",
    "280. La mayor parte de la gente prefiere ganar a perder.",
    "281. Paso poco tiempo con mi familia.",
    "282. Soy capaz de resolver mis problemas por mi cuenta.",
    (
        "283. Algunas partes de mi cuerpo han quedado paralizadas en alguna"
        " ocasión."
    ),
    "284. No soy de las personas que se asustan fácilmente.",
    "285. Me controlo de una forma muy estricta.",
    "286. Casi siempre soy una persona alegre y positiva.",
    "287. Casi nunca compro cosas por un impulso repentino.",
    "288. La gente tiene que ganarse mi confianza.",
    (
        "289. Tengo visiones en las que me veo en la obligación de cometer"
        " ciertos delitos."
    ),
    "290. No creo que existan personas capaces de leer la mente.",
    "291. Nunca he robado dinero u objetos de otras personas.",
    "292. Me gusta hablar con otras personas sobre sus problemas de salud.",
    "293. Soy una persona afectuosa.",
    "294. Nunca conduzco si he estado bebiendo.",
    "295. Casi nunca bebo alcohol.",
    "296. La gente suele pedirme opinión.",
    "297. Si cuando acudo a un establecimiento me atienden mal reclamo al responsable.",
    "298. Regaño a las personas que se lo merecen.",
    "299. Trato de evitar el tener que elevar la voz.",
    "300. Me he preguntado cómo reaccionarían otras personas si me suicidase.",
    "301. Tengo muchos motivos para vivir.",
    "302. Comparto el consumo de drogas con mis mejores amigos.",
    "303. Soy una persona temeraria.",
    "304. A veces podría haber actuado más reflexivamente de lo que lo hice.",
    "305. No me preocupo por las cosas que escapan a mi control.",
    "306. No me preocupa viajar en autobús o en tren.",
    "307. Tengo bastante éxito en lo que emprendo.",
    "308. Soy incapaz de verme como una persona famosa.",
    "309. Soy objeto de una conspiración.",
    "310. Mantengo el contacto con mis amigos y amigas.",
    "311. Cuando hago una promesa no siento la necesidad de cumplirla.",
    "312. Tengo diarreas con frecuencia.",
    "313. Tengo el pulso firme.",
    "314. Evito ciertas cosas que me traen malos recuerdos.",
    "315. Tengo poco interés por el sexo.",
    (
        "316. Soy poco paciente con la gente que no está de acuerdo con mis"
        " planes."
    ),
    "317. A la larga uno siempre se ve recompensado si ayuda a los demás.",
    (
        "318. Soy capaz de concentrarme ahora tan bien como en mis mejores"
        " tiempos."
    ),
    "319. No soy del tipo de personas a las que asustan los retos.",
    (
        "320. En mi tiempo libre suelo leer, ver la televisión o simplemente"
        " descansar."
    ),
    "321. Me gustaría entender por qué actúo en la forma en que lo hago.",
    "322. Mi vida es completamente impredecible.",
    (
        "323. En algunas ocasiones mi vista ha empeorado y luego ha vuelto a"
        " mejorar."
    ),
    "324. Soy una persona muy tranquila y relajada.",
    "325. La gente dice que soy perfeccionista.",
    "326. Me satisface plenamente mi situación laboral.",
    "327. Me preocupa no tener bastante dinero para salir adelante.",
    "328. La relación con mi pareja no va bien.",
    (
        "329. Creo que dentro de mí hay tres o cuatro personalidades"
        " completamente diferentes."
    ),
    "330. Soy una persona bastante comprensiva.",
    "331. Es importante para mí tener relaciones personales íntimas.",
    "332. Tengo poca paciencia con la gente.",
    "333. Tengo más amigos que la mayor parte de la gente que conozco.",
    "334. Nunca he tenido problemas por haber bebido.",
    "335. He tenido algunos problemas en el trabajo por culpa de la bebida.",
    (
        "336. Suelo intentar que los demás no se den cuenta cuando discrepo de"
        " ellos."
    ),
    "337. Soy una persona muy independiente.",
    "338. La gente se sorprendería si me viese gritar a alguien.",
    (
        "339. Desde que soy una persona adulta nunca he empezado una pelea que"
        " haya llegado a las manos."
    ),
    "340. Estoy pensando en la posibilidad de suicidarme.",
    (
        "341. Las cosas nunca me han ido tan mal como para pensar en"
        " suicidarme."
    ),
    (
        "342. El consumo de drogas nunca me ha producido problemas con la"
        " familia o los amigos."
    ),
    "343. Pongo mucho cuidado en la forma de gastar el dinero.",
    "344. Casi nunca estoy de mal humor.",
]

OPCIONES_PAI = {
    "F": "F - Falso",
    "LV": "LV - Ligeramente verdadero",
    "BV": "BV - Bastante verdadero",
    "CV": "CV - Completamente verdadero",
}





MAPA_TESTS = {
    "LSB-50": "LSB-50",
    "MCMI-III": "MCMI-III",
    "CUIDA": "CUIDA",
    "STAI": "STAI",
    "BDI-II": "BDI-II",
    "PAI": "PAI",
}



st.sidebar.title("⚖️ Sistema Forense Online")
rol = st.sidebar.radio("¿Cómo querés ingresar?", ["🧑‍⚖️ Soy Perito (Admin)", "🧑 Soy Evaluado (con Token)"], index=0)

if rol == "🧑‍⚖️ Soy Perito (Admin)":
    st.title("Panel Perito - Control Central")
    if not st.session_state["perito_autenticado"]:
        pwd = st.text_input("Contraseña maestra", type="password")
        if st.button("Ingresar"):
            if pwd == CONTRASEÑA_MAESTRA:
                st.session_state["perito_autenticado"] = True
                st.rerun()
            else:
                st.error("Contraseña incorrecta")
        st.stop()

    col_act_global, col_info, col_cerrar = st.columns([2,2,1])
    with col_act_global:
        if st.button("🔄 ACTUALIZAR DATOS AHORA", type="primary", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    with col_info:
        st.caption(f"Actualizado: {datetime.now(TZ).strftime('%d/%m/%Y %H:%M:%S')}")
    with col_cerrar:
        if st.button("Cerrar sesion"):
            st.session_state["perito_autenticado"] = False
            st.rerun()

    st.divider()
    st.subheader("1️⃣ Crear nuevo protocolo")
    st.caption("El evaluado completará sus datos (nombre, DNI, localidad) y consentimiento. Vos solo generás el código.")

    if st.button("Generar Link + Token", type="primary"):
        nuevo_token = generar_token_unico()
        ip, ua = obtener_metadatos_conexion()
        guardar_token_db(nuevo_token, {
            "estado": "activa",
            "datos_persona": {},
            "evaluaciones": {},
            "ip_acceso": ip,
            "user_agent": ua
        })
        st.success(f"¡Clave generada!: {nuevo_token}")
        base_url = "https://psi-forense-knto5bo9aobIpy73lw34o6.streamlit.app"
        link_completo = f"{base_url}/?token={nuevo_token}"
        st.code(link_completo, language="text")
        st.info("Copiá este link y envialo por WhatsApp. Podés quedarte como Perito logueado y probar en incógnito. El evaluado puede hacer los 6 tests con el mismo código.")

    st.divider()
    st.subheader("📋 Estado de Claves y Evaluaciones - Código de Protocolo")

    datos = cargar_datos_db()

    if not datos:
        st.warning("Aún no hay protocolos generados.")
    else:
        import pandas as pd, io, json
        filas=[]
        for tok,info in datos.items():
            dp=info.get("datos_persona") or {}
            evals=info.get("evaluaciones") or {}
            filas.append({
                "Token":tok,
                "Nombre":f"{dp.get('nombre','')} {dp.get('apellido','')}".strip() or "-",
                "DNI":dp.get('dni','-'),
                "Localidad":dp.get('localidad','-'),
                "Consent": "Sí" if dp.get('consentimiento') else "No",
                "Tests": ", ".join(evals.keys()) if evals else "-"
            })
        df=pd.DataFrame(filas)
        import io as io_module
        output_excel = io_module.BytesIO()
        excel_ok = False
        try:
            with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name="Resumen", index=False)
            excel_ok = True
        except ModuleNotFoundError:
            try:
                output_excel = io_module.BytesIO()
                with pd.ExcelWriter(output_excel, engine='xlsxwriter') as writer:
                    df.to_excel(writer, sheet_name="Resumen", index=False)
                excel_ok = True
            except Exception:
                excel_ok = False
        except Exception as e:
            st.error(f"No se pudo generar Excel: {e}")
            excel_ok = False

        if excel_ok:
            output_excel.seek(0)
            st.download_button("📊 DESCARGAR EXCEL DE TODOS (Resumen)", data=output_excel, file_name=f"forense_{datetime.now(TZ).strftime('%Y%m%d_%H%M')}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        else:
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.warning("openpyxl no disponible, descargando CSV")
            st.download_button("📊 DESCARGAR CSV DE TODOS", data=csv_data, file_name=f"forense_{datetime.now(TZ).strftime('%Y%m%d_%H%M')}.csv", mime="text/csv")
        
        # --- NUEVO: Excel global con TODAS las preguntas y respuestas ---
        try:
            import io as io_mod2
            output_global_det = io_mod2.BytesIO()
            try:
                import openpyxl
                engine2 = 'openpyxl'
            except:
                engine2 = 'xlsxwriter'
            
            with pd.ExcelWriter(output_global_det, engine=engine2) as writer2:
                # Hoja resumen igual que antes
                df.to_excel(writer2, sheet_name="Resumen Protocolos", index=False)
                
                # Hoja detalle larga con todas las respuestas + preguntas
                filas_detalle=[]
                for tok, inf in datos.items():
                    dp2 = inf.get("datos_persona") or {}
                    evs2 = inf.get("evaluaciones") or {}
                    for test_n, resp_dict in evs2.items():
                        for p_k, r_v in resp_dict.items():
                            try:
                                n = int(p_k.split('_')[1]) - 1
                            except:
                                n = 0
                            preg = p_k
                            etiqueta = str(r_v)
                            try:
                                if "LSB-50" in test_n and n < len(ITEMS_LSB50):
                                    preg = ITEMS_LSB50[n]
                                    etiqueta = OPCIONES_LSB50.get(str(r_v), str(r_v))
                                elif "MCMI-III" in test_n and n < len(ITEMS_MCMIIII):
                                    preg = ITEMS_MCMIIII[n]
                                elif "MCMI-IV" in test_n and n < len(ITEMS_MCMI_IV):
                                    preg = ITEMS_MCMI_IV[n]
                                elif "CUIDA" in test_n and n < len(ITEMS_CUIDA):
                                    preg = ITEMS_CUIDA[n]
                                    etiqueta = OPCIONES_CUIDA.get(str(r_v), str(r_v))
                                elif "STAI" in test_n and n < len(ITEMS_STAI):
                                    preg = ITEMS_STAI[n]
                                elif "BDI-II" in test_n and n < len(ITEMS_BDI):
                                    preg = ITEMS_BDI[n].get('titulo','')
                                    etiqueta = str(r_v)
                                elif "PAI" in test_n and n < len(ITEMS_PAI):
                                    preg = ITEMS_PAI[n]
                                    etiqueta = OPCIONES_PAI.get(str(r_v), str(r_v))
                            except:
                                pass
                            filas_detalle.append({
                                "Token": tok,
                                "Nombre": f"{dp2.get('nombre','')} {dp2.get('apellido','')}".strip(),
                                "DNI": dp2.get('dni',''),
                                "Localidad": dp2.get('localidad',''),
                                "Test": test_n,
                                "Nº": n+1,
                                "Pregunta": preg,
                                "Respuesta_Valor": r_v,
                                "Respuesta_Texto": etiqueta
                            })
                if filas_detalle:
                    pd.DataFrame(filas_detalle).to_excel(writer2, sheet_name="Detalle con Preguntas", index=False)
            
            output_global_det.seek(0)
            st.download_button(
                "📥 DESCARGAR EXCEL GLOBAL CON PREGUNTAS",
                data=output_global_det,
                file_name=f"forense_GLOBAL_CON_PREGUNTAS_{datetime.now(TZ).strftime('%Y%m%d_%H%M')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key="dl_global_preguntas",
                type="secondary",
                use_container_width=True
            )
        except Exception as e:
            st.warning(f"No se pudo generar Excel global con preguntas: {e}")


        st.divider()

        for clave in list(datos.keys()):
            info = datos[clave]
            persona = info.get("datos_persona") or {}
            evals = info.get("evaluaciones", {})

            col_texto, col_btn_ver, col_actualizar, col_borrar = st.columns([3.5, 1.8, 1.2, 1.0])

            with col_texto:
                estado_actual = info.get("estado", "activa")
                if estado_actual in ["finalizada", "cerrada", "completada"]:
                    nombre_str = f"{persona.get('nombre','')} {persona.get('apellido','')}".strip() or "Evaluado"
                    tests_realizados = ", ".join(list(evals.keys())) if evals else "sin tests"
                    st.markdown(f"🔒 **Código:** `{clave}` | **{nombre_str}** | {tests_realizados} | **CERRADO**")
                elif evals:
                    nombre_str = f"{persona.get('nombre','')} {persona.get('apellido','')}".strip() or "Evaluado"
                    tests_realizados = ", ".join(list(evals.keys()))
                    st.markdown(f"🔴 **Código:** `{clave}` | **{nombre_str}** | **{tests_realizados}**")
                elif persona.get('nombre'):
                    st.markdown(f"🟡 **Código:** `{clave}` | **{persona.get('nombre')} {persona.get('apellido')}** | Datos completados")
                else:
                    st.markdown(f"🟢 **Código:** `{clave}` | **Disponible**")

            with col_btn_ver:
                if persona or evals:
                    if f"modal_ver_{clave}" not in st.session_state:
                        st.session_state[f"modal_ver_{clave}"] = False
                    btn_label = "👁️ Ocultar" if st.session_state[f"modal_ver_{clave}"] else "👁️ Ver Protocolo" if evals else "👤 Ver Datos"
                    if st.button(btn_label, key=f"btn_ver_{clave}", use_container_width=True):
                        st.session_state[f"modal_ver_{clave}"] = not st.session_state[f"modal_ver_{clave}"]
                        st.rerun()
                else:
                    st.write("_Sin datos_")

            with col_actualizar:
                if st.button("🔄 Actualizar", key=f"btn_actualizar_{clave}", use_container_width=True):
                    st.rerun()

            with col_borrar:
                if st.button("🗑️ Borrar", key=f"btn_borrar_{clave}", use_container_width=True):
                    if f"modal_ver_{clave}" in st.session_state:
                        del st.session_state[f"modal_ver_{clave}"]
                    eliminar_token_db(clave)
                    st.rerun()
            
            # Botón reactivar si está finalizado
            estado_actual = info.get("estado", "activa")
            if estado_actual in ["finalizada", "cerrada", "completada"]:
                if st.button("♻️ Reactivar", key=f"btn_reactivar_{clave}", use_container_width=True):
                    info["estado"] = "activa"
                    guardar_token_db(clave, info)
                    st.success(f"Token {clave} reactivado")
                    st.rerun()

            if st.session_state.get(f"modal_ver_{clave}", False):
                with st.container():
                    st.info(f"### 🛡️ Protocolo Forense - {clave}")
                    if persona:
                        st.write(f"**Nombre:** {persona.get('nombre','')} {persona.get('apellido','')}")
                        st.write(f"**Edad:** {persona.get('edad','-')}")
                        st.write(f"**DNI:** {persona.get('dni','-')}")
                        st.write(f"**Localidad:** {persona.get('localidad','-')}")
                        st.write(f"**Consentimiento:** {'✅ Sí - ' + persona.get('fecha_consentimiento','') if persona.get('consentimiento') else '❌ No'}")
                    st.write(f"**IP:** `{info.get('ip_acceso','-')}`")
                    st.write(f"**User-Agent:** `{info.get('user_agent','-')[:80]}`")
                    st.write(f"**Hash del Bloque (Inalterabilidad):** `{info.get('hash_bloque','-')}`")
                    # Generar hash de identidad para mostrar también
                    import hashlib
                    identidad_str = f"{persona.get('dni','')}-{persona.get('nombre','')}-{persona.get('apellido','')}"
                    hash_id = hashlib.sha256(identidad_str.encode()).hexdigest()[:16] if identidad_str.strip('-') else "-"
                    st.write(f"**Hash de Identidad (Integridad filiatoria):** `{hash_id}`")
                    st.write(f"**Fecha Creación:** {info.get('fecha_creacion','-')}")
                    st.write(f"**Última Actualización:** {info.get('fecha_actualizacion','-')}")
                    if evals:
                        st.write("---")
                        st.write("#### 📊 Respuestas con preguntas y puntaje:")
                        for test_nombre, respuestas_dict in evals.items():
                            st.markdown(f"**{test_nombre}**")
                            try:
                                tabla=[]
                                for p_key, resp_val in respuestas_dict.items():
                                    try:
                                        num = int(p_key.split('_')[1]) - 1
                                    except:
                                        num = 0
                                    pregunta_texto = p_key
                                    puntaje_texto = str(resp_val)
                                    try:
                                        if "LSB-50" in test_nombre and num < len(ITEMS_LSB50):
                                            pregunta_texto = ITEMS_LSB50[num]
                                            etiqueta = OPCIONES_LSB50.get(str(resp_val), OPCIONES_LSB50.get(resp_val, str(resp_val)))
                                            puntaje_texto = f"{resp_val} - {etiqueta}"
                                        elif "MCMI-III" in test_nombre and num < len(ITEMS_MCMIIII):
                                            pregunta_texto = ITEMS_MCMIIII[num]
                                        elif "CUIDA" in test_nombre and num < len(ITEMS_CUIDA):
                                            pregunta_texto = ITEMS_CUIDA[num]
                                            etiqueta = OPCIONES_CUIDA.get(str(resp_val), OPCIONES_CUIDA.get(resp_val, str(resp_val)))
                                            puntaje_texto = f"{resp_val} - {etiqueta}"
                                        elif "STAI" in test_nombre and num < len(ITEMS_STAI):
                                            pregunta_texto = ITEMS_STAI[num]
                                        elif "BDI-II" in test_nombre and num < len(ITEMS_BDI):
                                            pregunta_texto = ITEMS_BDI[num].get('titulo', f"Ítem {num+1}")
                                        elif "PAI" in test_nombre and num < len(ITEMS_PAI):
                                            pregunta_texto = ITEMS_PAI[num]
                                    except:
                                        pass
                                    tabla.append({"Nº": num+1, "Pregunta": pregunta_texto, "Respuesta": puntaje_texto})
                                df_r = pd.DataFrame(tabla)
                                st.dataframe(df_r, hide_index=True, use_container_width=True)
                            except Exception as e:
                                st.json(respuestas_dict)
                        # --- GENERAR EXCEL CON PREGUNTAS PARA ESTE PROTOCOLO ---
                        try:
                            import io as io_mod
                            import pandas as pd
                            output_det = io_mod.BytesIO()
                            try:
                                engine = 'openpyxl'
                                # Probar si existe
                                import openpyxl
                            except:
                                engine = 'xlsxwriter'
                            
                            with pd.ExcelWriter(output_det, engine=engine) as writer:
                                # Hoja 1: Datos filiatorios
                                datos_filia = {
                                    "Campo": ["Código Protocolo", "Nombre", "Apellido", "Edad", "DNI", "Localidad", "Consentimiento", "Fecha Consentimiento", "IP", "Hash Bloque", "Hash Identidad", "Fecha Creación", "Actualización"],
                                    "Valor": [
                                        clave,
                                        persona.get('nombre',''),
                                        persona.get('apellido',''),
                                        persona.get('edad',''),
                                        persona.get('dni',''),
                                        persona.get('localidad',''),
                                        "Sí" if persona.get('consentimiento') else "No",
                                        persona.get('fecha_consentimiento',''),
                                        info.get('ip_acceso',''),
                                        info.get('hash_bloque',''),
                                        hash_id,
                                        info.get('fecha_creacion',''),
                                        info.get('fecha_actualizacion','')
                                    ]
                                }
                                pd.DataFrame(datos_filia).to_excel(writer, sheet_name="Datos Personales", index=False)
                                
                                # Una hoja por test con preguntas
                                for test_nombre, respuestas_dict in evals.items():
                                    tabla_excel=[]
                                    for p_key, resp_val in respuestas_dict.items():
                                        try:
                                            num = int(p_key.split('_')[1]) - 1
                                        except:
                                            num = 0
                                        pregunta_texto = p_key
                                        resp_valor = resp_val
                                        resp_etiqueta = str(resp_val)
                                        try:
                                            if "LSB-50" in test_nombre and num < len(ITEMS_LSB50):
                                                pregunta_texto = ITEMS_LSB50[num]
                                                resp_etiqueta = OPCIONES_LSB50.get(str(resp_val), OPCIONES_LSB50.get(resp_val, str(resp_val)))
                                            elif "MCMI-III" in test_nombre and num < len(ITEMS_MCMIIII):
                                                pregunta_texto = ITEMS_MCMIIII[num]
                                            elif "MCMI-IV" in test_nombre and num < len(ITEMS_MCMI_IV):
                                                pregunta_texto = ITEMS_MCMI_IV[num]
                                            elif "CUIDA" in test_nombre and num < len(ITEMS_CUIDA):
                                                pregunta_texto = ITEMS_CUIDA[num]
                                                resp_etiqueta = OPCIONES_CUIDA.get(str(resp_val), OPCIONES_CUIDA.get(resp_val, str(resp_val)))
                                            elif "STAI" in test_nombre and num < len(ITEMS_STAI):
                                                pregunta_texto = ITEMS_STAI[num]
                                                resp_etiqueta = OPCIONES_STAI.get(str(resp_val), OPCIONES_STAI.get(resp_val, str(resp_val)))
                                            elif "BDI-II" in test_nombre and num < len(ITEMS_BDI):
                                                item = ITEMS_BDI[num]
                                                pregunta_texto = item.get('titulo', f"Ítem {num+1}")
                                                # Para BDI, resp es el texto elegido
                                                resp_etiqueta = str(resp_val)
                                            elif "PAI" in test_nombre and num < len(ITEMS_PAI):
                                                pregunta_texto = ITEMS_PAI[num]
                                                resp_etiqueta = OPCIONES_PAI.get(str(resp_val), str(resp_val))
                                        except:
                                            pass
                                        tabla_excel.append({
                                            "Nº": num+1,
                                            "Pregunta": pregunta_texto,
                                            "Respuesta_Valor": resp_valor,
                                            "Respuesta_Texto": resp_etiqueta
                                        })
                                    # Ordenar por Nº
                                    df_excel = pd.DataFrame(tabla_excel).sort_values("Nº")
                                    # Nombre de hoja máximo 31 caracteres
                                    sheet_name = test_nombre[:31]
                                    df_excel.to_excel(writer, sheet_name=sheet_name, index=False)
                            
                            output_det.seek(0)
                            st.download_button(
                                f"📥 DESCARGAR EXCEL CON PREGUNTAS - {clave}",
                                data=output_det,
                                file_name=f"Protocolo_{clave}_{persona.get('apellido','Evaluado')}_{test_nombre[:10]}_CON_PREGUNTAS.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                key=f"dl_excel_preguntas_{clave}",
                                type="primary",
                                use_container_width=True
                            )
                        except Exception as e:
                            st.error(f"No se pudo generar Excel con preguntas: {e}")
                st.divider()

else:
    st.title("Evaluación Psicológica Forense")
    
    # Manejo de token por URL o manual - SIMPLE Y FUNCIONAL
    query_params = st.query_params
    token_url = query_params.get("token", None)
    
    # Si viene por URL y no hay token actual, usarlo
    if token_url and not st.session_state.get("token_actual"):
        st.session_state["token_actual"] = token_url.strip().upper()
    
    c_tok, c_btn = st.columns([4,1])
    with c_tok:
        token_input = st.text_input("Ingresá tu TOKEN", value=st.session_state.get("token_actual",""), placeholder="EVAL-XXXXXX", key="token_input_final", autocomplete="off")
    with c_btn:
        st.write("")
        st.write("")
        btn_entrar = st.button("Entrar", type="primary", use_container_width=True)

    # Si aprieta Entrar, guardar
    if btn_entrar:
        if token_input:
            nuevo = token_input.strip().upper()
            # Si cambia de token, resetear estado
            if st.session_state.get("token_actual") != nuevo:
                st.session_state["test_enviado"] = False
            st.session_state["token_actual"] = nuevo
            st.rerun()
    
    # Si el usuario escribe y presiona Enter (sin boton), Streamlit hace rerun y token_input ya tiene valor
    # Entonces si token_input != token_actual, actualizar
    if token_input and token_input.strip().upper() != st.session_state.get("token_actual"):
        # Solo si dio Enter (el valor cambió)
        pass  # El boton es el que confirma, para evitar que escribiendo se dispare

    token_actual = st.session_state.get("token_actual")
    if not token_actual:
        st.info("Pedile a tu perito el código y apretá Entrar. También podés entrar directo con el link ?token=EVAL-XXXX")
        st.stop()

    datos_db = cargar_datos_db()
    if token_actual not in datos_db:
        st.error(f"Código {token_actual} no existe o fue borrado. Pedí uno nuevo.")
        if st.button("Borrar código y volver"):
            st.session_state["token_actual"] = None
            st.rerun()
        st.stop()

    datos_token = datos_db[token_actual]
    # --- BLOQUEO DE RE-USO DE TOKEN (un solo uso) ---
    estado_token = datos_token.get("estado", "activa")
    if estado_token in ["finalizada", "cerrada", "completada", "finalizado", "cerrado"]:
        st.error(f"🔒 El protocolo {token_actual} ya fue cerrado y no puede reutilizarse por seguridad forense.")
        st.warning("Por inalterabilidad de la cadena de custodia, cada token es de un solo uso. Pedile al perito que te genere uno nuevo.")
        if st.button("Borrar código y solicitar uno nuevo"):
            st.session_state["token_actual"] = None
            st.session_state["test_enviado"] = False
            st.query_params.clear()
            st.rerun()
        st.stop()
    
    dp = datos_token.get("datos_persona") or {}
    datos_completos = all([dp.get('nombre'), dp.get('apellido'), dp.get('edad'), dp.get('dni'), dp.get('localidad'), dp.get('consentimiento')])

    if not datos_completos:
        st.success(f"Código válido: {token_actual}")
        st.subheader("Paso 1: Completá tus datos personales")
        with st.form("form_datos_personales"):
            c1, c2 = st.columns(2)
            nombre = c1.text_input("Nombre*", autocomplete="off")
            apellido = c2.text_input("Apellido*", autocomplete="off")
            c3, c4, c5 = st.columns(3)
            edad = c3.number_input("Edad*", min_value=6, max_value=100, value=18)
            dni = c4.text_input("DNI*", autocomplete="off")
            localidad = c5.text_input("Localidad donde vivís*", autocomplete="off")
            st.divider()
            st.markdown("### Consentimiento Informado\nUsted participará en evaluación psicológica forense. Datos confidenciales Ley 26.657.")
            consent = st.checkbox("✅ He leído y acepto el Consentimiento Informado*")
            if st.form_submit_button("Aceptar y Continuar a los Tests", type="primary", use_container_width=True):
                if not (nombre and apellido and dni and localidad and edad and consent):
                    st.error("Completá todo y aceptá consentimiento.")
                else:
                    dp.update({"nombre": nombre.strip(), "apellido": apellido.strip(), "edad": int(edad), "dni": dni.strip(), "localidad": localidad.strip(), "consentimiento": True, "fecha_consentimiento": datetime.now(TZ).strftime("%d/%m/%Y %H:%M")})
                    datos_token["datos_persona"] = dp
                    guardar_token_db(token_actual, datos_token)
                    st.rerun()
        st.stop()

    # Pantalla de enviado - permite hacer otro test sin cerrar
    if st.session_state.get("test_enviado"):
        evals_hechas = datos_token.get("evaluaciones", {})
        st.success(f"✅ Test enviado. Llevás {len(evals_hechas)} test(s) con este código.")
        for t in evals_hechas.keys():
            st.markdown(f"- ✅ {t}")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("📝 Realizar otro test", type="primary", use_container_width=True):
                st.session_state["test_enviado"] = False
                st.rerun()
        with c2:
            if st.button("🚪 Salir y CERRAR protocolo (un solo uso)", use_container_width=True, type="primary"):
                # Cerrar token por seguridad - no se podrá volver a entrar
                datos_token["estado"] = "finalizada"
                try:
                    guardar_token_db(token_actual, datos_token)
                except:
                    pass
                st.session_state["token_actual"] = None
                st.session_state["test_enviado"] = False
                st.query_params.clear()
                st.success("Protocolo cerrado correctamente. Ya no podrás volver a entrar con este código.")
                st.rerun()
        st.stop()

    st.success(f"Bienvenido/a {dp.get('nombre')} {dp.get('apellido')} | {dp.get('localidad')}")
    test_seleccionado = st.selectbox("Seleccioná el test", TESTS_DISPONIBLES)
    # --- Mostrar consigna oficial en hoja del evaluado ---
    key_map = {"LSB-50": "LSB-50", "MCMI-III": "MCMI-III", "MCMI-IV": "MCMI-IV", "CUIDA": "CUIDA", "STAI": "STAI", "BDI-II": "BDI-II", "PAI": "PAI"}
    test_key_tmp = None
    for k in key_map:
        if test_seleccionado.startswith(k):
            test_key_tmp = k
            break
    if test_key_tmp:
        render_consigna(test_key_tmp)

    if test_seleccionado.startswith("LSB-50"):
        st.subheader("LSB-50")
        respuestas={}
        with st.form("form_lsb50"):
            for idx, preg in enumerate(ITEMS_LSB50,1):
                respuestas[f"p_{idx}"] = st.radio(preg, options=list(OPCIONES_LSB50.keys()), format_func=lambda x: OPCIONES_LSB50[x], horizontal=True, key=f"lsb_{idx}_{token_actual}")
                st.divider()
            if st.form_submit_button("Guardar y Enviar LSB-50", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["LSB-50"]=respuestas
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("MCMI-III"):
        st.subheader("MCMI-III")
        respuestas_mcmi={}
        with st.form("form_mcmi3"):
            for idx, preg in enumerate(ITEMS_MCMIIII,1):
                respuestas_mcmi[f"p_{idx}"] = st.radio(preg, options=OPCIONES_MCMI, horizontal=True, key=f"mcmi_{idx}_{token_actual}")
                if idx % 15 == 0: st.divider()
            if st.form_submit_button("Guardar y Enviar MCMI-III", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["MCMI-III"]=respuestas_mcmi
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("MCMI-IV"):
        st.subheader("MCMI-IV - Versión Vigente DSM-5 (195 ítems)")
        st.warning("⚠️ Módulo MCMI-IV: reemplace los placeholders por los 195 ítems oficiales con licencia TEA/Pearson.")
        respuestas_mcmi4={}
        with st.form("form_mcmi4"):
            for idx, preg in enumerate(ITEMS_MCMI_IV,1):
                respuestas_mcmi4[f"p_{idx}"] = st.radio(preg, options=OPCIONES_MCMI, horizontal=True, key=f"mcmi4_{idx}_{token_actual}")
                if idx % 15 == 0: st.divider()
            if st.form_submit_button("Guardar y Enviar MCMI-IV", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["MCMI-IV"]=respuestas_mcmi4
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("CUIDA"):
        st.subheader("CUIDA")
        respuestas_cuida={}
        with st.form("form_cuida"):
            for idx, preg in enumerate(ITEMS_CUIDA,1):
                respuestas_cuida[f"p_{idx}"] = st.radio(preg, options=list(OPCIONES_CUIDA.keys()), format_func=lambda x: OPCIONES_CUIDA[x], horizontal=True, key=f"cuida_{idx}_{token_actual}")
                st.divider()
            if st.form_submit_button("Guardar y Enviar CUIDA", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["CUIDA"]=respuestas_cuida
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("STAI"):
        st.subheader("STAI")
        respuestas_stai={}
        with st.form("form_stai"):
            for idx, preg in enumerate(ITEMS_STAI,1):
                respuestas_stai[f"p_{idx}"] = st.radio(preg, options=list(OPCIONES_STAI.keys()), format_func=lambda x: OPCIONES_STAI[x], horizontal=True, key=f"stai_{idx}_{token_actual}")
                st.divider()
            if st.form_submit_button("Guardar y Enviar STAI", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["STAI"]=respuestas_stai
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("BDI-II"):
        st.subheader("BDI-II")
        respuestas_bdi={}
        with st.form("form_bdii"):
            for idx, item in enumerate(ITEMS_BDI,1):
                respuestas_bdi[f"p_{idx}"] = st.radio(item["titulo"], options=item["opciones"], key=f"bdi_{idx}_{token_actual}")
                st.divider()
            if st.form_submit_button("Guardar y Enviar BDI-II", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["BDI-II"]=respuestas_bdi
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
    elif test_seleccionado.startswith("PAI"):
        st.subheader("PAI")
        respuestas_pai={}
        with st.form("form_pai"):
            for idx, preg in enumerate(ITEMS_PAI,1):
                respuestas_pai[f"p_{idx}"] = st.radio(preg, options=list(OPCIONES_PAI.keys()), format_func=lambda x: OPCIONES_PAI[x], horizontal=True, key=f"pai_{idx}_{token_actual}")
                st.divider()
            if st.form_submit_button("Guardar y Enviar PAI", use_container_width=True, type="primary"):
                datos_token["evaluaciones"]["PAI"]=respuestas_pai
                guardar_token_db(token_actual, datos_token)
                st.session_state["test_enviado"]=True
                st.rerun()
