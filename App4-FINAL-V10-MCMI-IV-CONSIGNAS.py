
import hashlib
import json
import random
import sqlite3
import string
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import streamlit as st

st.set_page_config(page_title="Evaluaciones Psicologicas Forenses - V21 EGEP-5 + MCMI-IV", page_icon="⚖️", layout="wide")
hide_style = """
<style>
#MainMenu {visibility: hidden;} 
footer {visibility: hidden;} 
header {visibility: hidden;}

/* AUMENTAR LETRA PANEL LATERAL */
[data-testid="stSidebar"] h1 {
    font-size: 28px !important;
    font-weight: 800 !important;
}
[data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    font-size: 22px !important;
}
[data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] p {
    font-size: 18px !important;
    line-height: 1.4 !important;
}
[data-testid="stSidebar"] .stRadio label {
    font-size: 19px !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label p {
    font-size: 18px !important;
}
</style>
"""
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
    "EGPT-5 / EGEP-5 (Evaluacion Global del Estres Postraumatico - DSM-5 - CON BAREMOS)",
    "STAI (Cuestionario de Ansiedad Estado-Rasgo)",
    "BDI-II (Inventario de Depresion de Beck)",
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
    "EGEP-5": """
    **EGPT-5 / EGEP-5 - Evaluación Global del Estrés Postraumático DSM-5 (Crespo, Gómez, et al.) - CON BAREMOS COLOMBIANOS Y ESPAÑOLES**

    Instrumento con baremos oficiales para peritaje de daño psíquico.

    **ESTRUCTURA:**
    - Sección 1 (13-26): Caracterización del acontecimiento traumático (gravedad, temporalidad, miedo/indefensión/horror, tipo de amenaza)
    - Sección 2 (27-49): Síntomas nucleares - Si/No + Grado de molestia 0-4 (Ninguna, Leve, Moderada, Grave, Extrema)
      - Intrusión (27-31) max 20, Evitación (32-33) max 8, Alteraciones cognitivas (34-40) max 28, Activación (41-46) max 24, Total max 80
      - Síntomas disociativos (47-49) especificador DSM-5
    - Sección 3 (50-58): Temporalidad y funcionamiento (médico, medicación, laboral, social, familiar)

    **BAREMOS:** Tabla A1 Baremos Colombianos (Pc 1-99) y Baremos Españoles - Permite convertir puntaje directo a percentil y nivel: No significativo, Leve, Moderado, Grave, Extremo.
    Corte clínico sugerido: Total ≥20 y criterios DSM-5 completos.

    Responda con sinceridad. No hay respuestas correctas o incorrectas para fines periciales.
    """,
    "EGPT-5": """
    **EGPT-5 / EGEP-5 - Evaluación Global del Estrés Postraumático DSM-5 - CON BAREMOS**
    Ver EGEP-5. Mismo instrumento. Baremos incluidos para dictamen pericial.
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
}

TIEMPO_ESTIMADO = {
    "LSB-50": "5-8 min", "MCMI-III": "25-30 min", "MCMI-IV": "25-35 min",
    "EGEP-5": "15-20 min", "EGPT-5": "15-20 min", "STAI": "8-10 min", "BDI-II": "5-7 min"
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

# --- MCMI-IV 195 items - cargados desde preg_195.txt ---
ITEMS_MCMI_IV = [
    "1. Últimamente parece que me quedo sin fuerzas, incluso por la mañana.",
    "2. Siempre me aseguro de que mi trabajo esté bien planeado y organizado.",
    "3. Disfruto haciendo tantas cosas diferentes que no puedo decidir por cuál empezar.",
    "4. Me preocupa que las personas de las que dependo me abandonen.",
    "5. Aunque me da miedo hacer amistades, me gustaría tener más de las que tengo.",
    "6. Raramente exteriorizo los pocos sentimientos que tengo.",
    "7. Me cuesta mantener el equilibrio cuando camino.",
    "8. Siempre busco oportunidades nuevas que me resulten emocionantes.",
    "9. Algunas veces puedo ser bastante duro y desagradable con mi familia.",
    "10. Me gusta ser el centro de atención.",
    "11. De adolescente tuve muchos problemas por mi mal comportamiento en la escuela o instituto.",
    "12. Me da miedo hacerme muy amigo de alguien porque podría acabar sintiéndome ridiculizado o avergonzado.",
    "13. Noto que la gente está hablando de mí cuando paso a su lado.",
    "14. Hace unos años comencé a sentirme un fracasado.",
    "15. Si puedo elegir, prefiero hacer las cosas solo.",
    "16. Últimamente he comenzado a sentir deseos de destrozar cosas.",
    "17. Las cosas que hoy van bien no durarán mucho tiempo.",
    "18. A veces, cuando las cosas empiezan a irme mal, me siento como si estuviera loco o fuera de la realidad.",
    "19. Hago lo que quiero sin preocuparme de las consecuencias que tenga en los demás.",
    "20. Afronto mis actividades diarias con mucha energía y persistencia.",
    "21. Nunca perdono una ofensa ni olvido una situación embarazosa que alguien me haya causado.",
    "22. Me siento extremadamente deprimido y triste gran parte del tiempo.",
    "23. Siempre tiendo a culparme cuando las cosas van mal.",
    "24. Hace mucho tiempo decidí que es mejor tener poca relación con la gente.",
    "25. Tengo un problema con el alcohol que nos ha creado dificultades a mí y a mi familia.",
    "26. Soy una persona socialmente muy reservada y tímida.",
    "27. Muchas veces me siento muy alegre y animado sin ninguna razón.",
    "28. En las últimas semanas me he sentido agotado sin ningún motivo en particular.",
    "29. Mi tiempo es más valioso que el de los demás.",
    "30. Siempre estoy buscando hacer nuevas amistades y conocer gente nueva.",
    "31. Desde hace unas semanas estoy muy nervioso.",
    "32. Simplemente, no he tenido la suerte que otras personas han tenido en la vida.",
    "33. Las ideas me dan vueltas en la cabeza una y otra vez y no desaparecen.",
    "34. Desde hace uno o dos años, al pensar sobre la vida, me siento muy triste y desanimado.",
    "35. Intento hacerlo todo tan perfecto como sea posible.",
    "36. Mi adicción a las drogas hizo que faltara al trabajo.",
    "37. Mi estado de ánimo varía mucho de un día para otro.",
    "38. Utilizo mi encanto para conseguir lo que quiero.",
    "39. A menudo pienso que no merezco las cosas buenas que me pasan.",
    "40. En el pasado me corté o autolesioné a propósito.",
    "41. Tengo la sensación de que no duermo, y me levanto tan cansado como al acostarme.",
    "42. A menudo dejo que los demás tomen por mí decisiones importantes.",
    "43. Parece que pocas cosas me entristecen o me alegran.",
    "44. A menudo tengo pensamientos extraños de los que desearía librarme.",
    "45. Tengo muchos problemas para controlar el impulso de beber alcohol en exceso.",
    "46. Hago amistades con mucha más facilidad que la mayoría de la gente que conozco.",
    "47. Me da vergüenza el maltrato que sufrí cuando era joven.",
    "48. Me parece muy bien que haya normas porque son una buena guía a seguir.",
    "49. El año pasado aparecí en la portada de varias revistas.",
    "50. A menudo me enfado con la gente que hace las cosas lentamente.",
    "51. Me paso la vida preocupándome por una cosa u otra.",
    "52. Siempre me pregunto cuál es la razón real de que alguien sea especialmente agradable conmigo.",
    "53. Mis actividades cotidianas me animan y motivan.",
    "54. Tengo muchas ideas que son avanzadas para los tiempos actuales.",
    "55. Desde que sufrí una conmoción cerebral grave, ya no puedo concentrarme en nada.",
    "56. Antes la gente decía que me interesaba y me entusiasmaba demasiado por muchas cosas.",
    "57. He perdido el apetito por completo, y la mayoría de las noches tengo problemas para dormir.",
    "58. Desde que era niño he ido perdiendo contacto con la realidad.",
    "59. No puedo sentir mucho placer porque no creo que lo merezca.",
    "60. Prefiero que me digan lo que tengo que hacer en lugar de decidir por mí mismo.",
    "61. Consumir drogas me ha causado discusiones con mi familia.",
    "62. El recuerdo de una experiencia muy perturbadora sigue presente en mis pensamientos y me obsesiona.",
    "63. La mayoría de la gente me considera una persona prudente y cuidadosa.",
    "64. Parece que he perdido el interés en la mayoría de las cosas que solía encontrar placenteras, como el sexo.",
    "65. He tenido problemas con la ley un par de veces.",
    "66. He tenido que ser muy duro con algunas personas para mantenerlas a raya.",
    "67. Estoy muy seguro de mí mismo.",
    "68. La gente intenta hacerme creer que estoy loco.",
    "69. Me doy atracones de comida un par de veces a la semana.",
    "70. Frecuentemente siento que no hay nada dentro de mí, como si estuviera vacío y hueco.",
    "71. Siempre me ha resultado difícil dejar de sentirme deprimido y triste.",
    "72. Cuando estoy solo y lejos de casa, a menudo comienzo a sentirme tenso y entro en pánico.",
    "73. La gente dice que soy una persona formal y con valores morales.",
    "74. Me cuesta controlar mi ira.",
    "75. Soy una persona muy optimista.",
    "76. Años después, aún tengo pesadillas sobre un hecho que fue una amenaza real para mi vida.",
    "77. Me parece que necesito que alguien me oriente para hacer las cosas.",
    "78. Recientemente he pensado muy en serio en quitarme la vida.",
    "79. Hay mala gente que intenta llevarse el mérito de lo que he hecho o pensado.",
    "80. Últimamente estoy destrozado.",
    "81. Consumir drogas puede ser irresponsable, pero en el pasado las he necesitado.",
    "82. Soy una persona muy variable, cambio de opinión y sentimientos continuamente.",
    "83. Se me da muy bien inventar excusas cuando me meto en problemas.",
    "84. Cuando estoy en una fiesta, nunca me aíslo de los demás.",
    "85. Parece que echo a perder las buenas oportunidades que se cruzan en mi camino.",
    "86. Algunas veces me provoco el vómito después de comer.",
    "87. Soy una persona especial, así que no me importa lo que piensen los demás.",
    "88. Observo atentamente a mi familia para saber en quién se puede confiar y en quién no.",
    "89. Ciertos pensamientos vuelven a mi mente una y otra vez.",
    "90. Pocas cosas en la vida me resultan placenteras.",
    "91. Me siento agitado y me cuesta conciliar el sueño porque tengo recuerdos dolorosos dando vueltas en mi cabeza.",
    "92. A menudo me pierdo en mis pensamientos y me olvido de lo que está pasando a mi alrededor.",
    "93. Nunca he podido dejar de sentir que no valgo nada para los demás.",
    "94. Tengo un problema con la bebida que he tratado de solucionar sin éxito.",
    "95. Alguien ha estado intentando controlar mi mente.",
    "96. La mayoría de las personas que han triunfado han tenido suerte o han sido deshonestas.",
    "97. A menudo irrito a la gente dándoles órdenes.",
    "98. No he visto un coche en los últimos diez años.",
    "99. Siempre me siento cohibido y tenso en las reuniones sociales.",
    "100. Creo que provoco situaciones en las que resulto herido o me siento rechazado.",
    "101. Me siento profundamente deprimido sin saber por qué.",
    "102. La gente dice que soy una persona delgada, pero creo que mis músculos y mi trasero son demasiado grandes.",
    "103. A menudo disfruto provocando una discusión o una pelea.",
    "104. Tengo mucho cuidado en mantener mi vida como algo privado, para que nadie pueda aprovecharse de mí.",
    "105. El consumo de drogas me ha causado muchos problemas.",
    "106. A menudo me echan la culpa por cosas de las que no soy responsable.",
    "107. Pensar en el futuro al comienzo de cada día me hace sentir extremadamente deprimido.",
    "108. A veces las personas se molestan conmigo porque dicen que hablo mucho o demasiado deprisa.",
    "109. Yo nunca podría arreglármelas solo.",
    "110. Mi cabeza no funciona bien desde que hace unos años tuve una lesión cerebral.",
    "111. Me siento solo y vacío la mayor parte del tiempo.",
    "112. La gente se burla de mí a mis espaldas.",
    "113. Últimamente sudo mucho y me siento muy tenso.",
    "114. Estas últimas semanas me he sentido cada vez más triste.",
    "115. Me enfurezco rápidamente con la gente que me molesta.",
    "116. A veces no he podido pasar el día sin tomar drogas.",
    "117. Me gusta mucho coquetear.",
    "118. Ya no tengo energía para concentrarme en mis responsabilidades diarias.",
    "119. Mis emociones no parecen ser tan intensas como las del resto de la gente.",
    "120. Me siento débil y cansado la mayor parte del tiempo.",
    "121. Ideas extrañas entran en mi mente, dan vueltas y vueltas en mi cabeza, y no desaparecen.",
    "122. Los demás tienen oportunidades que yo no tengo.",
    "123. Repito ciertos comportamientos una y otra vez, algunas veces para reducir mi ansiedad y otras para evitar que pase algo malo.",
    "124. He tomado medicación que no me habían recetado.",
    "125. Mi vida actual todavía se ve afectada por recuerdos e imágenes de algo terrible que me pasó.",
    "126. A menudo echo a perder las cosas buenas que me ocurren.",
    "127. Voces malvadas intentan apoderarse de mi mente.",
    "128. Me siento muy culpable cuando pierdo el control.",
    "129. Mi entusiasmo por el trabajo que hago nunca disminuye.",
    "130. Supongo que no soy diferente de mis padres ya que, en cierto modo, me he convertido en un alcohólico.",
    "131. Últimamente tengo que pensar las cosas una y otra vez sin ningún motivo.",
    "132. Animo a los demás a que admiren lo que digo o hago.",
    "133. Dejo de hacer cosas si tengo que hacerlas solo.",
    "134. He intentado suicidarme.",
    "135. Soy una persona miedosa y reservada.",
    "136. A las personas que supuestamente son mis amigos les gustaría hacerme daño.",
    "137. A menudo me dejo llevar por la rabia y luego me siento muy culpable.",
    "138. A menudo oigo cosas con tanta claridad que me molesta.",
    "139. Aparte de mi familia, tengo muy pocos amigos íntimos.",
    "140. La desorganización me hace sentir muy incómodo.",
    "141. A menudo critico mucho a la gente que me irrita.",
    "142. Tengo muchas cualidades que los demás querrían tener.",
    "143. Terribles acontecimientos de mi pasado reaparecen obsesivamente en mis pensamientos y sueños.",
    "144. Sé que he gastado más dinero en droga del que debería.",
    "145. A menudo, y antes de darme cuenta, me pongo a gritar enfadado a mis amigos y familiares.",
    "146. Me preocupa que mi cuerpo se desgaste rápidamente.",
    "147. Está bien burlar la ley si es poco probable que te atrapen.",
    "148. Creo que hay una conspiración contra mí.",
    "149. Soy una persona solitaria y no me molesta.",
    "150. Todavía me aterrorizo cuando pienso en una experiencia traumática que tuve hace años.",
    "151. Últimamente me he sentido muy culpable porque ya no soy capaz de hacer nada bien.",
    "152. Los castigos nunca me impidieron hacer lo que quería.",
    "153. Pocas veces creo lo que la gente me dice.",
    "154. Soy una persona muy sociable y extrovertida.",
    "155. Me entusiasmo con casi todo lo que hago.",
    "156. Estoy confundido sobre quién soy.",
    "157. Odio pensar en el maltrato que sufrí en mi infancia.",
    "158. Nunca infringiría la ley, aunque pudiera salir impune.",
    "159. Algunos miembros de mi familia dicen que soy egoísta y que solo pienso en mí.",
    "160. En el último año he cruzado el Atlántico en avión 30 veces.",
    "161. Beber alcohol me ayuda cuando me siento deprimido.",
    "162. Preferiría seguir a alguien antes que ser yo el líder.",
    "163. A menudo me vienen ideas a la mente mucho más rápido de lo que puedo expresarlas.",
    "164. A menudo me siento tan mal que quiero hacerme daño de verdad.",
    "165. Algunas personas dicen que soy extraño o raro.",
    "166. A veces encuentro consuelo en mi sufrimiento.",
    "167. A menudo creo que me han tratado injustamente.",
    "168. Muestro mi enfado rápidamente a las personas que no están de acuerdo conmigo.",
    "169. Casi siempre me siento culpable sin ninguna razón aparente.",
    "170. Desde hace algún tiempo me siento triste y deprimido y parece que no consigo animarme.",
    "171. Sé cómo seducir a la gente.",
    "172. Siempre he tenido que estar atento a la gente que intenta engañarme.",
    "173. Siempre estoy dispuesto a aceptar lo que a los demás les gustaría hacer.",
    "174. Afronto todos los retos de la vida con una actitud valiente y enérgica.",
    "175. Nunca siento que tenga algo interesante que aportar a una conversación.",
    "176. Si mi medicamento no me hace efecto, es probable que lo tome con más frecuencia o aumente la dosis.",
    "177. En muchos periodos de mi vida he estado tan animado y he consumido tanta energía que luego me he sentido muy bajo de ánimo.",
    "178. A menudo me siento muy infeliz conmigo mismo.",
    "179. No me gusta cambiar mi rutina.",
    "180. No necesito tener amigos íntimos como tienen los demás.",
    "181. A veces me ha reconfortado herirme físicamente.",
    "182. Mucha gente ha estado espiando mi vida privada durante años.",
    "183. Cuando quiero, se me da bastante bien engañar a la gente.",
    "184. Incluso cuando las cosas van bien, creo que pronto irán mal.",
    "185. Se me da muy bien animar y motivar a los demás.",
    "186. Estoy dispuesto a pasar hambre para estar aún más delgado de lo que estoy.",
    "187. A menudo estoy irritable y de mal humor.",
    "188. Siempre intento acabar mi trabajo antes de dedicar tiempo a actividades de ocio.",
    "189. Solo las personas excepcionales pueden comprender mis capacidades.",
    "190. Realmente no entiendo los sentimientos humanos como los entienden los demás.",
    "191. Demasiadas normas impiden que haga lo que quiero.",
    "192. A veces siento que merezco ser infeliz.",
    "193. He estado abatido y triste gran parte de mi vida.",
    "194. Tiendo a estar de acuerdo con las opiniones de los demás.",
    "195. Evito la mayoría de las situaciones sociales porque creo que la gente me rechazará."
]




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


# ==================== EGPT-5 / EGEP-5 - EVALUACION GLOBAL DEL ESTRES POSTRAUMATICO DSM-5 - CON BAREMOS ====================
ITEMS_EGEP5_EVENTOS = [
    "1. Desastres naturales (inundaciones, huracanes, tornados, terremotos...)",
    "2. Accidentes de medios de transporte (coche, tren, avión, barco...)",
    "3. Otro tipo de accidentes (laborales, industriales, domésticos, actividades de ocio...)",
    "4. Combate o exposición a zona de guerra (en el ejército o como civil)",
    "5. Violación, abuso o ataque sexual",
    "6. Acoso (sexual, en el trabajo, en antiguas relaciones...) o maltrato psicológico",
    "7. Violencia física (ataques, asaltos, maltrato...)",
    "8. Actos terroristas o tortura",
    "9. Encarcelamiento, detención o cautividad forzosa",
    "10. Muerte accidental o violenta de una persona o de un ser querido",
    "11. Cualquier otro acontecimiento o experiencia estresante (especificar)",
]

ITEMS_EGEP5_ACONTECIMIENTO = [
    "13. Valore la gravedad del acontecimiento: Leve, Moderada, Grave, Extrema",
    "14. ¿Cuándo sufrió ese acontecimiento por primera vez? (Infancia/adolescencia, Hace >3 meses, Hace >1 mes y <3 meses, Último mes)",
    "15. Ese acontecimiento ocurrió... (una única ocasión, varias ocasiones, de forma repetida/reiterada)",
    "16. Durante ese acontecimiento, ¿se sintió con mucho miedo? (Sí/No)",
    "17. Durante ese acontecimiento, ¿se sintió indefenso? (Sí/No)",
    "18. Durante ese acontecimiento, ¿se sintió horrorizado? (Sí/No)",
    "19. Ese acontecimiento supuso una lesión grave para usted (Sí/No)",
    "20. Ese acontecimiento supuso lesión grave o muerte de otras personas (Sí/No)",
    "21. Ese acontecimiento supuso amenaza para su integridad física (Sí/No)",
    "22. Ese acontecimiento supuso amenaza para la integridad física de otras personas (Sí/No)",
    "23. Ese acontecimiento supuso amenaza para su vida (Sí/No)",
    "24. Ese acontecimiento supuso amenaza para la vida de otras personas (Sí/No)",
    "25. Ese acontecimiento supuso escenas desagradables (Sí/No)",
    "26. Ese acontecimiento supuso amenazas para su dignidad personal, honor o estabilidad emocional (Sí/No)",
]

ITEMS_EGEP5_SINTOMAS = [
    "27. Tiene recuerdos desagradables y repetitivos sobre el acontecimiento (imágenes o pensamientos) [Intrusión]",
    "28. Tiene sueños desagradables y repetitivos sobre el acontecimiento [Intrusión]",
    "29. Hay momentos en que actúa o se siente como si estuviera viviendo de nuevo el acontecimiento [Intrusión]",
    "30. Siente malestar (nerviosismo, inquietud...) cuando algo le recuerda el acontecimiento [Intrusión]",
    "31. Los recuerdos sobre el acontecimiento hacen que tiemble, sude, se le acelere el corazón... [Intrusión]",
    "32. Intenta evitar o ahuyentar pensamientos, sentimientos o conversaciones relacionadas con el acontecimiento [Evitación]",
    "33. Intenta evitar actividades, lugares o personas que le recuerdan el acontecimiento [Evitación]",
    "34. Tiene dificultades para recordar aspectos importantes del acontecimiento [Cognición]",
    "35. Siente que no puede confiar en los demás [Cognición]",
    "36. Se ha sentido culpable por algo que hizo o dejó de hacer durante el acontecimiento [Cognición]",
    "37. Tiene constantemente sentimientos negativos (miedo, horror, ira, culpa, vergüenza...) [Cognición]",
    "38. Ha disminuido su interés o el placer en cosas con las que solía disfrutar [Cognición]",
    "39. Tiene sensación de distancia o alejamiento de los demás [Cognición]",
    "40. Tiene dificultades para experimentar ciertas emociones (amor, felicidad, ternura, deseo sexual) [Cognición]",
    "41. Se siente irritable o tiene ataques de ira [Activación]",
    "42. Lleva a cabo conductas que sabe que son peligrosas o que pueden causarle daño [Activación]",
    "43. Está en constante estado de alerta o vigilancia (siempre en guardia) [Activación]",
    "44. Se sobresalta o asusta fácilmente [Activación]",
    "45. Tiene dificultades para concentrarse [Activación]",
    "46. Tiene dificultades para dormirse o mantener el sueño [Activación]",
    "47. Hay momentos en que se siente como si estuviera fuera de su cuerpo, como si se viera desde fuera [Disociativo]",
    "48. Hay momentos en que se siente fuera de contacto con lo que sucede a su alrededor (como en una nube o sueño) [Disociativo]",
    "49. Hay momentos en que siente que las cosas que pasan a su alrededor son irreales o muy extrañas [Disociativo]",
]

ITEMS_EGEP5_TEMPORALIDAD = [
    "50. ¿Desde cuándo experimenta estos problemas? (<1 mes, >1 mes y <3 meses, >3 meses)",
    "51. ¿Cuánto tiempo tardaron en aparecer estos problemas tras el acontecimiento? (Nada más ocurrir, 6 primeros meses, 6 meses o más después - presentación demorada)",
]

ITEMS_EGEP5_FUNCIONAMIENTO = [
    "52. ¿Ha consultado al médico por alguno de estos problemas? (Sí/No)",
    "53. ¿Ha tomado medicación por alguno de estos problemas? (Sí/No)",
    "54. ¿Ha tomado alcohol o drogas para hacer frente a estos problemas? (Sí/No)",
    "55. ¿Ha afectado negativamente su vida laboral/académica? (Sí/No)",
    "56. ¿Ha afectado negativamente sus relaciones sociales? (Sí/No)",
    "57. ¿Ha afectado negativamente sus relaciones familiares o de pareja? (Sí/No)",
    "58. ¿Ha afectado a algún otro aspecto importante de su vida? (Sí/No) - Especificar",
]

ITEMS_EGSR = ITEMS_EGEP5_SINTOMAS
ITEMS_EGSR_DISOCIATIVOS = ITEMS_EGEP5_SINTOMAS[20:23]
ITEMS_EGSR_DISFUNCIONALIDAD = ITEMS_EGEP5_FUNCIONAMIENTO

OPCIONES_EGEP5_SINO = ["No", "Sí"]
OPCIONES_EGEP5_GRAVEDAD_ACONT = ["Leve", "Moderada", "Grave", "Extrema"]
OPCIONES_EGEP5_TEMPORAL = ["En la infancia o adolescencia", "Hace más de 3 meses", "Hace más de 1 mes pero menos de 3 meses", "En el último mes"]
OPCIONES_EGEP5_FRECUENCIA = ["En una única ocasión", "En varias ocasiones", "De forma repetida o reiterada"]
OPCIONES_EGEP5_MOLESTIA = {
    0: "0 - Ninguna",
    1: "1 - Leve",
    2: "2 - Moderada",
    3: "3 - Grave",
    4: "4 - Extrema",
}
OPCIONES_EGSR = OPCIONES_EGEP5_MOLESTIA
OPCIONES_EGEP5 = OPCIONES_EGEP5_MOLESTIA

BAREMOS_EGEP5_COLOMBIANOS = {
    99: {"I": (27,28), "E": None, "C": (27,28), "A": (21,24), "Total": (71,80), "F": None},
    98: {"I": (20,20), "E": None, "C": (21,26), "A": (19,20), "Total": (61,70), "F": (7,7)},
    97: {"I": (19,19), "E": None, "C": (20,20), "A": (18,18), "Total": (59,60), "F": None},
    96: {"I": (17,18), "E": None, "C": (19,19), "A": (17,17), "Total": (55,58), "F": None},
    95: {"I": (16,16), "E": (8,8), "C": (17,18), "A": (16,16), "Total": (51,54), "F": (6,6)},
    90: {"I": (15,15), "E": (6,7), "C": (15,16), "A": (15,15), "Total": (44,50), "F": None},
    85: {"I": (14,14), "E": None, "C": (14,14), "A": (14,14), "Total": (40,43), "F": (5,5)},
    80: {"I": (13,13), "E": (5,5), "C": (13,13), "A": None, "Total": (39,39), "F": None},
    75: {"I": (12,12), "E": None, "C": (11,12), "A": (12,13), "Total": (36,38), "F": (4,4)},
    70: {"I": (11,11), "E": None, "C": None, "A": (11,11), "Total": (35,35), "F": None},
    65: {"I": None, "E": None, "C": (10,10), "A": (10,10), "Total": (33,34), "F": None},
    60: {"I": (10,10), "E": (4,4), "C": (8,9), "A": (8,9), "Total": (30,32), "F": (3,3)},
    55: {"I": None, "E": None, "C": (6,7), "A": None, "Total": (28,29), "F": None},
    50: {"I": (8,9), "E": (3,3), "C": None, "A": (7,7), "Total": (25,27), "F": None},
    45: {"I": None, "E": None, "C": (5,5), "A": (6,6), "Total": (22,24), "F": (2,2)},
    40: {"I": (6,7), "E": None, "C": (4,4), "A": (5,5), "Total": (20,21), "F": None},
    35: {"I": (5,5), "E": (2,2), "C": None, "A": None, "Total": (17,19), "F": None},
    30: {"I": None, "E": (1,1), "C": (3,3), "A": (4,4), "Total": (15,16), "F": (1,1)},
    25: {"I": (4,4), "E": (0,0), "C": (2,2), "A": None, "Total": (13,14), "F": (0,0)},
    20: {"I": (3,3), "E": None, "C": (1,1), "A": (3,3), "Total": (10,12), "F": None},
    15: {"I": (2,2), "E": None, "C": (0,0), "A": (2,2), "Total": (8,9), "F": None},
    10: {"I": (1,1), "E": None, "C": None, "A": (1,1), "Total": (6,7), "F": None},
    5: {"I": (0,0), "E": None, "C": None, "A": (0,0), "Total": (3,5), "F": None},
    3: {"I": None, "E": None, "C": None, "A": None, "Total": (1,2), "F": None},
    1: {"I": None, "E": None, "C": None, "A": None, "Total": (0,0), "F": None},
}

def obtener_percentil_egep5(puntaje, escala="Total"):
    for pc in sorted(BAREMOS_EGEP5_COLOMBIANOS.keys(), reverse=True):
        rango = BAREMOS_EGEP5_COLOMBIANOS[pc].get(escala)
        if rango is None:
            continue
        if rango[0] <= puntaje <= rango[1]:
            return pc
    for pc in sorted(BAREMOS_EGEP5_COLOMBIANOS.keys(), reverse=True):
        rango = BAREMOS_EGEP5_COLOMBIANOS[pc].get(escala)
        if rango and puntaje >= rango[0]:
            return pc
    return 1

def interpretar_egep5(total):
    if total >= 51:
        return "Extremo (Pc 95-99) - Grave, compatible con TEPT severo"
    elif total >= 40:
        return "Grave (Pc 85-90) - TEPT moderado-grave"
    elif total >= 25:
        return "Moderado (Pc 50-75) - Sintomatologia significativa"
    elif total >= 13:
        return "Leve (Pc 25-45) - Sintomatologia leve-moderada"
    else:
        return "No significativo (Pc <25) - Sin indicadores clinicos de TEPT"






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

# ITEMS_PAI eliminado en V20 - reemplazado por EGS-R









MAPA_TESTS = {
    "LSB-50": "LSB-50",
    "MCMI-III": "MCMI-III",
    "CIT": "CIT",
    "STAI": "STAI",
    "BDI-II": "BDI-II",
    "PAI": "PAI",
}



# --- DETECCIÓN AUTOMÁTICA DE LINK DE WHATSAPP ---
# Si viene ?token= en la URL, forzar modo Evaluado para que no pida contraseña maestra
query_params_init = st.query_params
token_init = query_params_init.get("token", None)
if token_init:
    token_init_clean = token_init.strip().upper()
    if not st.session_state.get("token_actual"):
        st.session_state["token_actual"] = token_init_clean
    # Forzar rol evaluado
    rol = "🧑 Soy Evaluado (con Token)"
    st.sidebar.title("⚖️ Sistema Forense Online")
    st.sidebar.success(f"Link detectado: {token_init_clean}")
    st.sidebar.info("Ingresando como Evaluado")
else:
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
        base_url = "https://mcmi-iv-nqsfb7xqw7vbyzpcrcene6.streamlit.app"  # URL real detectada
        link_completo = f"{base_url}/?token={nuevo_token}"
        st.code(link_completo, language="text")
        st.success("✅ Link listo para WhatsApp - entra directo como Evaluado sin pedir contraseña")
        st.info("Cuando el evaluado abra este link, entra automáticamente a 'Soy Evaluado' y no le pide contraseña maestra. Probalo en incógnito.")

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
                                elif ("EGEP" in test_n or "EGPT" in test_n) and True:
                                    preg = ITEMS_EGEP5_SINTOMAS[n] if n < len(ITEMS_EGEP5_SINTOMAS) else f"Item EGEP-5 {n+1}"
                                    etiqueta = OPCIONES_EGEP5_MOLESTIA.get(int(r_v), str(r_v)) if str(r_v).isdigit() else str(r_v)
                                elif "STAI" in test_n and n < len(ITEMS_STAI):
                                    preg = ITEMS_STAI[n]
                                elif "BDI-II" in test_n and n < len(ITEMS_BDI):
                                    preg = ITEMS_BDI[n].get('titulo','')
                                    etiqueta = str(r_v)
                                elif "EGS-R" in test_n and "dis_" in str(n):
                                    preg = f"Síntoma disociativo {n}"
                                    etiqueta = OPCIONES_EGEP5_MOLESTIA.get(int(r_v), str(r_v)) if str(r_v).isdigit() else str(r_v)

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
                                        elif "EGS-R" in test_nombre and num < len(ITEMS_EGSR):
                                            pregunta_texto = ITEMS_EGSR[num]
                                            etiqueta = OPCIONES_EGEP5_MOLESTIA.get(int(resp_val), str(resp_val)) if str(resp_val).isdigit() else str(resp_val)
                                            puntaje_texto = f"{resp_val} - {etiqueta}"
                                        elif "STAI" in test_nombre and num < len(ITEMS_STAI):
                                            pregunta_texto = ITEMS_STAI[num]
                                        elif "BDI-II" in test_nombre and num < len(ITEMS_BDI):
                                            pregunta_texto = ITEMS_BDI[num].get('titulo', f"Ítem {num+1}")
                                        # PAI eliminado - EGS-R reemplazo
                                        elif False and "PAI" in test_nombre:
                                            pass
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
                                            elif "EGS-R" in test_nombre and num < len(ITEMS_EGSR):
                                                pregunta_texto = ITEMS_EGSR[num]
                                                resp_etiqueta = OPCIONES_EGEP5_MOLESTIA.get(int(resp_val), str(resp_val)) if str(resp_val).isdigit() else str(resp_val)
                                            elif "STAI" in test_nombre and num < len(ITEMS_STAI):
                                                pregunta_texto = ITEMS_STAI[num]
                                                resp_etiqueta = OPCIONES_STAI.get(str(resp_val), OPCIONES_STAI.get(resp_val, str(resp_val)))
                                            elif "BDI-II" in test_nombre and num < len(ITEMS_BDI):
                                                item = ITEMS_BDI[num]
                                                pregunta_texto = item.get('titulo', f"Ítem {num+1}")
                                                # Para BDI, resp es el texto elegido
                                                resp_etiqueta = str(resp_val)
                                            # PAI eliminado
                                            elif False and "PAI" in test_nombre:
                                                pass
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
    # --- PASO 1: Datos personales (simplificado: Esperanza ya cubre residencia) ---
    datos_personales_completos = all([dp.get('nombre'), dp.get('apellido'), dp.get('edad'), dp.get('dni'), dp.get('localidad'), dp.get('nacionalidad')])
    datos_completos = all([datos_personales_completos, dp.get('consentimiento')])

    if not datos_personales_completos:
        st.success(f"Código válido: {token_actual}")
        st.subheader("Paso 1: Completá tus datos personales")
        with st.form("form_datos_personales"):
            c1, c2 = st.columns(2)
            nombre = c1.text_input("Nombre*", value=dp.get('nombre',''), autocomplete="off")
            apellido = c2.text_input("Apellido*", value=dp.get('apellido',''), autocomplete="off")
            c3, c4, c5, c6 = st.columns(4)
            edad = c3.number_input("Edad*", min_value=6, max_value=100, value=int(dp.get('edad',18)) if dp.get('edad') else 18)
            dni = c4.text_input("DNI*", value=dp.get('dni',''), autocomplete="off")
            nacionalidad = c5.text_input("Nacionalidad*", value=dp.get('nacionalidad','Argentina'), autocomplete="off")
            localidad = c6.text_input("Localidad*", value=dp.get('localidad','ESPERANZA'), autocomplete="off")
            if st.form_submit_button("Guardar datos y pasar al Consentimiento", type="primary", use_container_width=True):
                if not (nombre and apellido and dni and localidad and nacionalidad and edad):
                    st.error("Completá todos los campos obligatorios.")
                else:
                    dp.update({
                        "nombre": nombre.strip(), 
                        "apellido": apellido.strip(), 
                        "edad": int(edad), 
                        "dni": dni.strip(), 
                        "localidad": localidad.strip(), 
                        "nacionalidad": nacionalidad.strip()
                    })
                    datos_token["datos_persona"] = dp
                    guardar_token_db(token_actual, datos_token)
                    st.rerun()
        st.stop()

    if not dp.get('consentimiento'):
        st.success(f"Datos guardados: {dp.get('nombre')} {dp.get('apellido')} - DNI {dp.get('dni')}")
        st.subheader("Paso 2: Consentimiento Informado Tele Evaluación Psicológica")
        st.info("Consentimiento autogenerado con hora oficial Argentina (GMT-3 Buenos Aires). Quedará guardado con firma digital.")

        # Autocompletado con hora Argentina - sin inputs manuales
        ahora_ba = datetime.now(TZ)
        # Formato: ESPERANZA - 20/09/2026 20:12 ART (GMT-3)
        lugar_fecha_auto = f"{dp.get('localidad','ESPERANZA').upper()} - {ahora_ba.strftime('%d/%m/%Y %H:%M')} ART (GMT-3 Buenos Aires)"
        dias_map = ["lunes","martes","miércoles","jueves","viernes","sábado","domingo"]
        dia_nombre = dias_map[ahora_ba.weekday()]
        
        # Valores fijos autocompletados
        lic_auto = "Aldo Montoya"
        plataforma_auto = "Google Meet / Zoom"
        dias_auto = f"{dia_nombre} {ahora_ba.strftime('%d/%m/%Y')}"
        anio_auto = str(ahora_ba.year)
        
        with st.form("form_consentimiento_tele"):
            st.markdown("### CONSENTIMIENTO INFORMADO TELE EVALUACIÓN PSICOLÓGICA")
            
            st.markdown(f"**Lugar y Fecha (hora oficial Argentina):** {lugar_fecha_auto}")
            st.caption(f"Sincronizado con America/Argentina/Buenos_Aires - {ahora_ba.isoformat()}")
            
            st.markdown(f"**Yo:** {dp.get('nombre')} {dp.get('apellido')} **identificado con DNI:** {dp.get('dni')} **de Nacionalidad:** {dp.get('nacionalidad')} - **Localidad:** {dp.get('localidad')}")

            st.divider()
            # Texto legal final - AUTOCOMPLETADO con hora BA
            texto_consent = f"""
            **Lugar y Fecha:** {lugar_fecha_auto}

            Yo **{dp.get('nombre')} {dp.get('apellido')}** identificado con **DNI {dp.get('dni')}** de Nacionalidad **{dp.get('nacionalidad')}**

            Declaro que conozco los objetivos y las fases del Proceso de Peritación Psicológica llevado a cabo por la/el **Lic. {lic_auto}** con el propósito de elevar un Informe Psicológico.

            Estoy dispuesto(a) a iniciar dicho proceso, siendo consciente que su contenido versa sobre diversos aspectos de mi historia vital. He sido informado que los encuentros se realizarán por la plataforma **{plataforma_auto}**, el día **{dias_auto}** (hora oficial Argentina GMT-3) y que debo mantener el micrófono y la cámara constantemente encendidas, por tanto, firmo de manera voluntaria, bajo ningún tipo de imposición este documento.
            """
            st.markdown(texto_consent)

            st.divider()
            consent_check = st.checkbox("✅ He leído, comprendido y acepto voluntariamente el Consentimiento Informado para Tele Evaluación*", value=False)
            firma_check = st.checkbox("✅ Confirmo que mis datos (Nombre, DNI, Nacionalidad) son correctos y firmo digitalmente este documento*", value=False)

            if st.form_submit_button("Firmar y Continuar a los Tests", type="primary", use_container_width=True):
                if not (consent_check and firma_check):
                    st.error("Tildá ambas casillas para firmar digitalmente.")
                else:
                    # Guardar todo - autocompletado con hora BA
                    texto_final = f"CONSENTIMIENTO INFORMADO TELE EVALUACION PSICOLOGICA - Lugar y Fecha: {lugar_fecha_auto} - Yo {dp.get('nombre')} {dp.get('apellido')} identificado con DNI {dp.get('dni')} de Nacionalidad {dp.get('nacionalidad')} Localidad {dp.get('localidad')} - Lic {lic_auto} - Plataforma {plataforma_auto} dia {dias_auto} anio {anio_auto} - Hora oficial {ahora_ba.isoformat()} - Acepta mantener microfono y camara encendidas - Firma voluntaria"
                    dp.update({
                        "consent_lugar_fecha": lugar_fecha_auto,
                        "consent_lic": lic_auto,
                        "consent_plataforma": plataforma_auto,
                        "consent_dias": dias_auto,
                        "consent_anio": anio_auto,
                        "consent_texto_final": texto_final,
                        "consentimiento": True,
                        "fecha_consentimiento": ahora_ba.strftime("%d/%m/%Y %H:%M"),
                        "fecha_consentimiento_iso": ahora_ba.isoformat()
                    })
                    datos_token["datos_persona"] = dp
                    guardar_token_db(token_actual, datos_token)
                    st.success("Consentimiento firmado correctamente.")
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
    key_map = {"LSB-50": "LSB-50", "MCMI-III": "MCMI-III", "MCMI-IV": "MCMI-IV", "EGPT-5": "EGEP-5", "EGEP-5": "EGEP-5", "STAI": "STAI", "BDI-II": "BDI-II"}
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
        # st.warning eliminado - ítems oficiales cargados
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
    elif test_seleccionado.startswith("EGPT") or test_seleccionado.startswith("EGEP"):
        st.subheader("EGPT-5 / EGEP-5 - Evaluación Global del Estrés Postraumático DSM-5 (CON BAREMOS)")
        st.info("**Instrumento con baremos oficiales - Para peritaje de daño psíquico civil/laboral** - Pc y niveles de gravedad incluidos")
        respuestas_egep={}
        with st.form("form_egep5"):
            st.markdown("### SECCIÓN 1: ACONTECIMIENTOS (Items 1-12) - Historia de exposición")
            st.caption("Para cada acontecimiento marque si: Me sucedió / Lo presencié directamente / Le sucedió a alguien cercano. Puede marcar varias columnas.")
            for idx, evento in enumerate(ITEMS_EGEP5_EVENTOS, 1):
                st.markdown(f"**{evento}**")
                col_a, col_b, col_c = st.columns(3)
                me_sucedio = col_a.checkbox(f"Me sucedió {idx}", key=f"egep_evt_me_{idx}_{token_actual}")
                presencie = col_b.checkbox(f"Lo presencié {idx}", key=f"egep_evt_pres_{idx}_{token_actual}")
                cercano = col_c.checkbox(f"A alguien cercano {idx}", key=f"egep_evt_cerc_{idx}_{token_actual}")
                respuestas_egep[f"evt_{idx}_me"] = me_sucedio
                respuestas_egep[f"evt_{idx}_pres"] = presencie
                respuestas_egep[f"evt_{idx}_cerc"] = cercano
                if idx == 11:
                    otro_desc = st.text_input(f"Especifique otro acontecimiento (11):", key=f"egep_evt_11_desc_{token_actual}")
                    respuestas_egep["evt_11_desc"] = otro_desc
                st.divider()
            
            st.markdown("**12. Indique cuál de los acontecimientos marcados es el que le ha causado o le causa más molestias (rodee con un círculo) - Señale solo uno:**")
            evento_mas_molesto = st.selectbox("Evento más molesto:", [f"{i}. {ev}" for i, ev in enumerate(ITEMS_EGEP5_EVENTOS,1)], key=f"egep_evento_molesto_{token_actual}")
            desc_evento = st.text_area("12. Describa brevemente el acontecimiento que acaba de indicar (el que más molestias causa):", key=f"egep_desc_evento_{token_actual}")
            
            st.divider()
            st.markdown("### Sección 1b: Caracterización del acontecimiento (Items 13-26)")
            c1,c2 = st.columns(2)
            gravedad_acont = c1.selectbox("13. Gravedad del acontecimiento:", OPCIONES_EGEP5_GRAVEDAD_ACONT, key=f"egep_grav_{token_actual}")
            cuando_primera = c2.selectbox("14. ¿Cuándo por primera vez?", OPCIONES_EGEP5_TEMPORAL, key=f"egep_cuando_{token_actual}")
            frecuencia = st.selectbox("15. Frecuencia del acontecimiento:", OPCIONES_EGEP5_FRECUENCIA, key=f"egep_frec_{token_actual}")
            st.markdown("Durante ese acontecimiento, usted se sintió...")
            col_miedo, col_indef, col_horror = st.columns(3)
            miedo = col_miedo.radio("16. ¿Miedo?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_miedo_{token_actual}")
            indefenso = col_indef.radio("17. ¿Indefenso?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_indef_{token_actual}")
            horrorizado = col_horror.radio("18. ¿Horrorizado?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_horror_{token_actual}")
            st.markdown("Ese acontecimiento supuso...")
            les_grave = st.radio("19. ¿Lesión grave para usted?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_les_{token_actual}")
            les_otros = st.radio("20. ¿Lesión grave o muerte de otras personas?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_les_otros_{token_actual}")
            amenaza_int = st.radio("21. ¿Amenaza para su integridad física?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_am_int_{token_actual}")
            amenaza_int_otros = st.radio("22. ¿Amenaza para integridad física de otras personas?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_am_int_otros_{token_actual}")
            amenaza_vida = st.radio("23. ¿Amenaza para su vida?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_am_vida_{token_actual}")
            amenaza_vida_otros = st.radio("24. ¿Amenaza para vida de otras personas?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_am_vida_otros_{token_actual}")
            escenas_desag = st.radio("25. ¿Escenas desagradables?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_escenas_{token_actual}")
            amenaza_dign = st.radio("26. ¿Amenazas para dignidad/honor/estabilidad emocional?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_dign_{token_actual}")
            
            st.divider()
            st.markdown("### Sección 2: Síntomas (27-49) - Marque Sí/No y grado 0-4")
            st.caption("0=Ninguna | 1=Leve | 2=Moderada | 3=Grave | 4=Extrema - Solo puntúe si respondió Sí")
            for idx, preg in enumerate(ITEMS_EGEP5_SINTOMAS,27):
                st.markdown(f"**{preg}**")
                col_si, col_grado = st.columns([1,3])
                con_si = col_si.radio(f"¿Presente? {idx}", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_si_{idx}_{token_actual}", label_visibility="collapsed")
                grado = col_grado.radio(f"Grado {idx}", options=list(OPCIONES_EGEP5_MOLESTIA.keys()), format_func=lambda x: OPCIONES_EGEP5_MOLESTIA[x], horizontal=True, key=f"egep_grado_{idx}_{token_actual}")
                if con_si == "No":
                    respuestas_egep[f"p_{idx}_si"] = "No"
                    respuestas_egep[f"p_{idx}_grado"] = 0
                else:
                    respuestas_egep[f"p_{idx}_si"] = "Sí"
                    respuestas_egep[f"p_{idx}_grado"] = grado
                st.divider()
            
            st.markdown("### Sección 3: Temporalidad y funcionamiento (50-58)")
            desde_cuando = st.selectbox("50. ¿Desde cuándo experimenta estos problemas?", ["<1 mes", ">1 mes y <3 meses", ">3 meses"], key=f"egep_50_{token_actual}")
            tiempo_aparicion = st.selectbox("51. ¿Cuánto tardaron en aparecer tras el acontecimiento?", ["Nada más ocurrir", "Durante los 6 primeros meses", "6 meses o más después (presentación demorada)"], key=f"egep_51_{token_actual}")
            consulta_med = st.radio("52. ¿Consultó al médico?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_52_{token_actual}")
            medicacion = st.radio("53. ¿Tomó medicación?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_53_{token_actual}")
            alcohol_drogas = st.radio("54. ¿Alcohol/drogas para afrontar?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_54_{token_actual}")
            afecta_laboral = st.radio("55. ¿Afectó vida laboral/académica?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_55_{token_actual}")
            afecta_social = st.radio("56. ¿Afectó relaciones sociales?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_56_{token_actual}")
            afecta_familiar = st.radio("57. ¿Afectó relaciones familiares/pareja?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_57_{token_actual}")
            afecta_otro = st.radio("58. ¿Afectó otro aspecto importante?", OPCIONES_EGEP5_SINO, horizontal=True, key=f"egep_58_{token_actual}")
            afecta_otro_desc = st.text_area("Especifique otro aspecto (58):", key=f"egep_58_desc_{token_actual}")

            if st.form_submit_button("Guardar y Enviar EGPT-5 / EGEP-5 (CON BAREMOS)", use_container_width=True, type="primary"):
                respuestas_egep["evento_mas_molesto"] = evento_mas_molesto
                respuestas_egep["descripcion_evento_12"] = desc_evento
                respuestas_egep["acont_gravedad"] = gravedad_acont
                respuestas_egep["acont_cuando"] = cuando_primera
                respuestas_egep["acont_frecuencia"] = frecuencia
                respuestas_egep["acont_miedo"] = miedo
                respuestas_egep["acont_indefenso"] = indefenso
                respuestas_egep["acont_horrorizado"] = horrorizado
                respuestas_egep["acont_lesion_grave"] = les_grave
                respuestas_egep["acont_lesion_otros"] = les_otros
                respuestas_egep["acont_amenaza_integridad"] = amenaza_int
                respuestas_egep["acont_amenaza_integridad_otros"] = amenaza_int_otros
                respuestas_egep["acont_amenaza_vida"] = amenaza_vida
                respuestas_egep["acont_amenaza_vida_otros"] = amenaza_vida_otros
                respuestas_egep["acont_escenas_desag"] = escenas_desag
                respuestas_egep["acont_amenaza_dignidad"] = amenaza_dign
                respuestas_egep["temp_desde_cuando"] = desde_cuando
                respuestas_egep["temp_tiempo_aparicion"] = tiempo_aparicion
                respuestas_egep["func_medico"] = consulta_med
                respuestas_egep["func_medicacion"] = medicacion
                respuestas_egep["func_alcohol"] = alcohol_drogas
                respuestas_egep["func_laboral"] = afecta_laboral
                respuestas_egep["func_social"] = afecta_social
                respuestas_egep["func_familiar"] = afecta_familiar
                respuestas_egep["func_otro"] = afecta_otro
                respuestas_egep["func_otro_desc"] = afecta_otro_desc
                try:
                    I = sum([respuestas_egep.get(f"p_{i}_grado",0) for i in range(27,32)])
                    E = sum([respuestas_egep.get(f"p_{i}_grado",0) for i in range(32,34)])
                    C = sum([respuestas_egep.get(f"p_{i}_grado",0) for i in range(34,41)])
                    A = sum([respuestas_egep.get(f"p_{i}_grado",0) for i in range(41,47)])
                    Total = I+E+C+A
                    F = sum([1 for k in ["func_medico","func_medicacion","func_alcohol","func_laboral","func_social","func_familiar","func_otro"] if respuestas_egep.get(k)=="Sí"])
                    respuestas_egep["puntaje_I"] = I
                    respuestas_egep["puntaje_E"] = E
                    respuestas_egep["puntaje_C"] = C
                    respuestas_egep["puntaje_A"] = A
                    respuestas_egep["puntaje_Total"] = Total
                    respuestas_egep["puntaje_F"] = F
                    respuestas_egep["percentil_Total"] = obtener_percentil_egep5(Total, "Total")
                    respuestas_egep["interpretacion"] = interpretar_egep5(Total)
                except:
                    pass
                datos_token["evaluaciones"]["EGPT-5"]=respuestas_egep
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
# PAI eliminado en V20
