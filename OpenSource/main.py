import os
os.environ["QTWEBENGINE_REMOTE_DEBUGGING"] = "8888"
import secrets
import readability 

import sys
import shutil
import traceback
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QFormLayout, QComboBox, QLabel, QCompleter, QGroupBox,
    QVBoxLayout, QLineEdit, QPushButton, QHBoxLayout, QProgressBar, QFileDialog, QDialog, QTextEdit, QDialogButtonBox,
    QMessageBox, QMenu, QDockWidget, QListWidget, QListWidgetItem, QButtonGroup, QFrame, QCheckBox, QGridLayout,
    QColorDialog, QStyle, QTableWidget, QTableWidgetItem, QHeaderView, QFileIconProvider, QStatusBar
)
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineDownloadRequest,
    QWebEngineUrlRequestInterceptor, QWebEngineScript
)
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtCore import (
    QUrl, Qt, qVersion, QSettings, QObject, pyqtSlot, QVariant, pyqtSignal, QPoint,
    QStringListModel, QTimer, QEvent, QFileInfo, QSize, QRunnable, QThreadPool,
    QTranslator, QLocale, QLibraryInfo
)
from PyQt6.QtGui import QIcon, QDesktopServices, QActionGroup, QShortcut, QKeySequence, QPixmap, QPalette, QColor, QAction, QImage, QPainter
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

import json
import urllib.request
import base64
from urllib.parse import urlparse, quote_plus
import uuid
import fnmatch
import zipfile
import string
import time
import tempfile

def get_base_path():
    """
    Obtiene la ruta base de la aplicación,
    funciona tanto en desarrollo como en una aplicación empaquetada (frozen).
    """
    return os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

def get_asset_path(asset_name):
    """
    Obtiene la ruta absoluta a un recurso en la carpeta 'assets',
    funciona tanto en desarrollo como en una aplicación empaquetada (frozen).
    """
    return os.path.join(get_base_path(), "assets", asset_name)

def sanitize_filename(filename):
    """Removes invalid characters from a filename for Windows."""
    # Invalid characters in Windows filenames
    invalid_chars = '<>:"/\\|?*'
    return "".join(c for c in filename if c not in invalid_chars)

def apply_app_theme(settings):
    """Aplica el tema guardado a toda la aplicación al inicio."""
    theme = settings.value("theme", "Sistema")

    if theme == "Oscuro":
        app = QApplication.instance()
        app.setStyle("Fusion")

        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        
        dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(127, 127, 127))
        dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(127, 127, 127))
        dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(127, 127, 127))

        app.setPalette(dark_palette)
    elif theme == "Claro":
        app = QApplication.instance()
        app.setPalette(QApplication.style().standardPalette())

class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    """
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)

class Worker(QRunnable):
    """
    Worker thread that executes a function in the background.
    """
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception:
            exctype, value, tb = sys.exc_info()
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class AdBlockInterceptor(QWebEngineUrlRequestInterceptor):
    """Intercepta peticiones de red para bloquear anuncios y rastreadores."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.enabled = True
        self.ad_block_list = set()
        self.user_block_list = set()
        self.full_block_list = set()

    def setEnabled(self, enabled):
        self.enabled = enabled

    def _update_full_block_list(self):
        """Reconstruye la lista de bloqueo unificada y cacheada."""
        self.full_block_list = self.ad_block_list.union(self.user_block_list)
        print(f"Lista de bloqueo unificada actualizada con {len(self.full_block_list)} dominios.")

    def load_ad_block_list(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                domains = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                self.ad_block_list = domains
                print(f"Lista de bloqueo de anuncios cargada con {len(self.ad_block_list)} dominios.")
        except FileNotFoundError:
            print("Archivo de lista de bloqueo no encontrado. El bloqueador estará inactivo hasta que se actualice.")
            self.ad_block_list = set()
        self._update_full_block_list()

    def update_user_block_list(self, domains_text: str):
        self.user_block_list = {line.strip() for line in domains_text.splitlines() if line.strip()}
        print(f"Lista de bloqueo de usuario actualizada con {len(self.user_block_list)} dominios.")
        self._update_full_block_list()

    def interceptRequest(self, info):
        info.setHttpHeader(b"DNT", b"1")

        if not self.enabled or not self.full_block_list:
            return

        host = info.requestUrl().host()
        # Comprueba de forma eficiente si el host o cualquiera de sus dominios padre están en la lista de bloqueo.
        # Ejemplo: para "ads.example.com", comprueba "ads.example.com", "example.com".
        host_parts = host.split('.')
        for i in range(len(host_parts)):
            domain_to_check = ".".join(host_parts[i:])
            if domain_to_check in self.full_block_list:
                info.block(True)
                return

class CustomWebEnginePage(QWebEnginePage):
    """
    Una subclase de QWebEnginePage que muestra una página de error personalizada
    cuando la carga de una página falla (p. ej., por falta de conexión).
    """
    customDownloadRequested = pyqtSignal(QUrl)

    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        self._is_showing_internal_page = False
        self.loadFinished.connect(self._on_load_finished)

    def acceptNavigationRequest(self, url, type, isMainFrame):
        if isMainFrame:
            if self.url().toString() == "wemphix:security-warning":
                # Permitir la navegación desde nuestra página de advertencia (p. ej., "Volver" o "Continuar").
                self._is_showing_internal_page = False
                return super().acceptNavigationRequest(url, type, isMainFrame)

        if type == QWebEnginePage.NavigationType.NavigationTypeLinkClicked:
            scheme = url.scheme()
            internal_schemes = ["http", "https", "file", "wemphix", "about", "data", "blob"]
            if scheme not in internal_schemes:
                QDesktopServices.openUrl(url)
                return False

        if isMainFrame:
            if url.scheme() == 'http':
                if url.host() not in ["localhost", "127.0.0.1"]:
                    self._is_showing_internal_page = True
                    self._show_http_warning_page(url)
                    return False

        self._is_showing_internal_page = False
        return super().acceptNavigationRequest(url, type, isMainFrame)

    def createStandardContextMenu(self):
        menu = super().createStandardContextMenu()
        context_data = self.contextMenuData()

        self._add_link_save_action(menu, context_data)
        self._add_media_save_action(menu, context_data)
        self._add_pip_action(menu, context_data)

        return menu

    def _add_link_save_action(self, menu, context_data):
        if not context_data.linkUrl().isEmpty():
            menu.addSeparator()
            action = QAction("Guardar enlace como...", menu)
            action.triggered.connect(lambda: self.customDownloadRequested.emit(context_data.linkUrl()))
            menu.addAction(action)

    def _add_media_save_action(self, menu, context_data):
        if not context_data.mediaUrl().isEmpty():
            media_type = context_data.mediaType()
            action_text = ""
            if media_type == QWebEnginePage.MediaType.MediaTypeVideo:
                action_text = "Guardar video como..."
            elif media_type == QWebEnginePage.MediaType.MediaTypeAudio:
                action_text = "Guardar audio como..."
            
            if action_text:
                menu.addSeparator()
                action = QAction(action_text, menu)
                action.triggered.connect(lambda: self.customDownloadRequested.emit(context_data.mediaUrl()))
                menu.addAction(action)

    def _add_pip_action(self, menu, context_data):
        if context_data.mediaType() == QWebEnginePage.MediaType.MediaTypeVideo:
            menu.addSeparator()
            self.pip_action = QAction("Entrar en Picture-in-Picture", menu)
            self.pip_action.triggered.connect(self._trigger_pip)
            self.runJavaScript("!!document.pictureInPictureElement", 0, self._update_pip_action_text)
            menu.addAction(self.pip_action)

    def _update_pip_action_text(self, is_in_pip):
        if hasattr(self, 'pip_action'):
            if is_in_pip:
                self.pip_action.setText("Salir de Picture-in-Picture")
            else:
                self.pip_action.setText("Entrar en Picture-in-Picture")

    def _trigger_pip(self):
        js_code = """
        (function() {
            if (document.pictureInPictureElement) {
                document.exitPictureInPicture();
            } else {
                // This is a simplification, it targets the first video with a src attribute.
                // A more robust solution would use the click coordinates to find the element.
                const video = document.querySelector('video[src]');
                if (video && typeof video.requestPictureInPicture === 'function') {
                    video.requestPictureInPicture().catch(e => console.error("Error al iniciar PiP:", e));
                } else {
                    alert("No se encontró un video compatible para Picture-in-Picture en esta página.");
                }
            }
        })();
        """
        self.runJavaScript(js_code)

    def _on_load_finished(self, ok):
        if not ok:
            if self._is_showing_internal_page:
                return

            self._show_error_page()
        
        self._is_showing_internal_page = False

    def _show_error_page(self):
        image_path = get_asset_path("ConnectionFailed.png")

        if not os.path.exists(image_path):
            print(f"Advertencia: No se encontró la imagen de error en '{image_path}'")
            self.setHtml("<h1>Error de Carga</h1><p>No se pudo cargar la página y no se encontró la imagen de error.</p>", self.url())
            return

        try:
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            image_data_uri = f"data:image/png;base64,{encoded_string}"
        except Exception as e:
            print(f"Error al procesar la imagen de error: {e}")
            self.setHtml("<h1>Error de Carga</h1><p>No se pudo cargar la página. Error al procesar recursos internos.</p>", self.url())
            return

        palette = QApplication.instance().palette()
        is_dark_theme = palette.color(QPalette.ColorRole.Window).lightness() < 128

        bg_color = "#2b2b2b" if is_dark_theme else "#f1f3f4"
        text_color = "#dcdcdc" if is_dark_theme else "#202124"
        secondary_text_color = "#9a9a9a" if is_dark_theme else "#5f6368"
        img_filter = "filter: invert(1);" if not is_dark_theme else ""

        html = f"""
        <!DOCTYPE html>
        <html><head><title>Error de conexión</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: {bg_color}; color: {text_color}; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .container {{ display: flex; align-items: center; text-align: left; max-width: 600px; }}
            .image-container {{ margin-right: 40px; }}
            img {{ width: 80px; height: 80px; {img_filter} }}
            h1 {{ font-size: 22px; font-weight: 500; margin-top: 0; margin-bottom: 16px; }}
            p {{ font-size: 15px; color: {secondary_text_color}; line-height: 1.5; }}
        </style>
        </head><body>
            <div class="container">
                <div class="image-container">
                    <img src="{image_data_uri}" alt="Sin conexión">
                </div>
                <div>
                    <h1>No se puede acceder a este sitio</h1>
                    <p>Necesitas una conexión a Internet para poder navegar.<br>Comprueba tu red y vuelve a intentarlo.</p>
                </div>
            </div>
        </body></html>
        """
        self.setHtml(html, self.url())

    def _show_http_warning_page(self, target_url: QUrl):
        image_path = get_asset_path("WarningSecurity.png")

        if not os.path.exists(image_path):
            self.setHtml(f"<h1>Conexión no segura</h1><p>Estás intentando acceder a {target_url.host()}, que no es seguro.</p>", QUrl("wemphix:security-warning"))
            return

        try:
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            image_data_uri = f"data:image/png;base64,{encoded_string}"
        except Exception as e:
            self.setHtml(f"<h1>Conexión no segura</h1><p>Error al cargar recursos de advertencia. Estás intentando acceder a {target_url.host()}, que no es seguro.</p>", QUrl("wemphix:security-warning"))
            return

        palette = QApplication.instance().palette()
        is_dark_theme = palette.color(QPalette.ColorRole.Window).lightness() < 128
        bg_color = "#3c2e2e" if is_dark_theme else "#fef7f7"
        text_color = "#dcdcdc" if is_dark_theme else "#202124"
        secondary_text_color = "#9a9a9a" if is_dark_theme else "#5f6368"
        button_bg_color = "#5a5a5a" if is_dark_theme else "#e0e0e0"
        danger_color = "#f28b82" if is_dark_theme else "#d93025"
        danger_hover_bg = "rgba(242, 139, 130, 0.1)" if is_dark_theme else "#fce8e6"

        html = f"""
        <!DOCTYPE html>
        <html><head><title>Conexión no segura</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: {bg_color}; color: {text_color}; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .container {{ display: flex; align-items: center; text-align: left; max-width: 650px; padding: 20px; }}
            .image-container {{ margin-right: 40px; flex-shrink: 0; }}
            img {{ width: 80px; height: 80px; }}
            h1 {{ font-size: 22px; font-weight: 500; margin-top: 0; margin-bottom: 16px; }}
            p {{ font-size: 15px; color: {secondary_text_color}; line-height: 1.5; margin-bottom: 24px;}}
            .buttons a {{ text-decoration: none; padding: 10px 20px; border-radius: 5px; font-weight: 500; margin-right: 10px; display: inline-block; border: 1px solid transparent;}}
            .back-button {{ background-color: {button_bg_color}; color: {text_color}; border: 1px solid #9a9a9a; }}
            .proceed-button {{ background-color: transparent; color: {danger_color}; border: 1px solid {danger_color}; }}
            .proceed-button:hover {{ background-color: {danger_hover_bg}; }}
        </style>
        </head><body>
            <div class="container">
                <div class="image-container">
                    <img src="{image_data_uri}" alt="Advertencia de seguridad">
                </div>
                <div>
                    <h1>Tu conexión con este sitio no es segura</h1>
                    <p>El acceso a sitios no seguros (HTTP) está bloqueado para proteger tu información. Los atacantes podrían ver o cambiar los datos que envías o recibes a través de este sitio (como contraseñas o tarjetas de crédito).</p>
                    <div class="buttons">
                        <a href="javascript:history.back()" class="back-button">Volver</a>
                        <a href="{target_url.toString()}" class="proceed-button">Continuar a {target_url.host()}</a>
                    </div>
                </div>
            </div>
        </body></html>
        """
        self.setHtml(html, QUrl("wemphix:security-warning"))

class BrowserApi(QObject):
    """
    Objeto que se expone al entorno JavaScript de las páginas web.
    Permite que las extensiones interactúen con la aplicación principal del navegador.
    """
    tabAdded = pyqtSignal(QVariant, name='tabAdded')
    tabUpdated = pyqtSignal(QVariant, name='tabUpdated')
    onBrowserActionClicked = pyqtSignal(str, name='onBrowserActionClicked')
    onTabActivated = pyqtSignal(str, name='onTabActivated')
    tabRemoved = pyqtSignal(int, name='tabRemoved')

    def __init__(self, main_window):
        super().__init__()
        self._main_window = main_window

    @pyqtSlot(QVariant, result=QVariant)
    def createTab(self, properties):
        url = properties.get('url', 'https://www.google.com')
        active = properties.get('active', True)
        new_webview = self._main_window.agregar_pestana(url, focus=active)
        tab_widget = new_webview.parentWidget()
        return tab_widget.property("tab_id")

    @pyqtSlot(str, QVariant)
    def updateTab(self, tab_id, update_properties):
        if 'url' in update_properties:
            self._main_window._update_tab_url(tab_id, update_properties['url'])

    @pyqtSlot(str)
    def removeTab(self, tab_id):
        self._main_window._close_tab_by_id(tab_id)

    @pyqtSlot(QVariant, result=QVariant)
    def queryTabs(self, query_info):
        return self._main_window._query_tabs(query_info)

    @pyqtSlot(str)
    def addNewTab(self, url="https://google.com"):
        self._main_window.agregar_pestana(url)

    @pyqtSlot(str, str)
    def showNotification(self, title, message):
        QMessageBox.information(self._main_window, title, message)

    @pyqtSlot(result=QVariant)
    def getCurrentUrl(self):
        if (current_widget := self._main_window.tabs.currentWidget()) and (webview := current_widget.findChild(QWebEngineView)):
            return webview.url().toString()
        return ""

    @pyqtSlot(result=QVariant)
    def getAllTabs(self):
        tabs_info = []
        for i in range(self._main_window.tabs.count()):
            widget = self._main_window.tabs.widget(i)
            if webview := widget.findChild(QWebEngineView):
                tabs_info.append({
                    "id": widget.property("tab_id"),
                    "index": i,
                    "title": self._main_window.tabs.tabText(i),
                    "url": webview.url().toString()
                })
        return tabs_info

    @pyqtSlot(result=QVariant)
    def getBrowserInfo(self):
        return {
            "version": "1.1",
            "profilePath": self._main_window.profile_path,
            "isIncognito": self._main_window.is_incognito
        }

    @pyqtSlot(str, result=QVariant)
    def findLoginsForUrl(self, url):
        if not self._main_window.password_manager: return ""
        return self._main_window.password_manager.find_logins_for_url(url)

    @pyqtSlot(str, str, result=str)
    def getPasswordForLogin(self, url, username):
        if not self._main_window.password_manager:
            return ""
        if self._main_window.password_manager:
            return self._main_window.password_manager.get_password_for_login(url, username)
        return ""

class SettingsDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle(self.tr("Configuración"))
        self.setMinimumWidth(400)

        self.layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        # Mapeo para temas
        self.theme_map = {
            "Sistema": self.tr("Sistema"),
            "Claro": self.tr("Claro"),
            "Oscuro": self.tr("Oscuro")
        }
        self.reverse_theme_map = {v: k for k, v in self.theme_map.items()}

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(self.theme_map.values()))
        current_theme_key = self.main_window.settings.value("theme", "Sistema")
        self.theme_combo.setCurrentText(self.theme_map.get(current_theme_key, self.tr("Sistema")))
        self.theme_combo.currentTextChanged.connect(
            lambda text: self.main_window._apply_theme(self.reverse_theme_map.get(text, "Sistema"))
        )

        self.homepage_edit = QLineEdit()
        self.homepage_edit.setText(self.main_window.settings.value("homepage", "https://www.google.com"))
        self.homepage_edit.textChanged.connect(self._on_homepage_changed)

        self.search_engine_edit = QLineEdit()
        self.search_engine_edit.setPlaceholderText(self.tr("Ej: https://duckduckgo.com/?q={}"))
        self.search_engine_edit.setText(self.main_window.settings.value("search_engine", "https://www.google.com/search?q={}"))
        self.search_engine_edit.textChanged.connect(self._on_search_engine_changed)

        form_layout.addRow(self.tr("Tema de la aplicación:"), self.theme_combo)
        form_layout.addRow(self.tr("Página de inicio:"), self.homepage_edit)
        form_layout.addRow(self.tr("Motor de búsqueda:"), self.search_engine_edit)
        self.layout.addLayout(form_layout)

        self.layout.addSpacing(10)
        self.layout.addWidget(QLabel(self.tr("Sitios Bloqueados (uno por línea):")))
        self.block_list_edit = QTextEdit()
        self.block_list_edit.setPlaceholderText(self.tr("ejemplo.com\nsitio-molesto.org"))
        self.block_list_edit.setMinimumHeight(100)
        self.block_list_edit.setText(self.main_window.settings.value("user_block_list", ""))
        self.block_list_edit.textChanged.connect(self._on_block_list_changed)
        self.layout.addWidget(self.block_list_edit)

        self.layout.addStretch()

        info_label = QLabel(self.tr("Algunos cambios pueden requerir un reinicio."))
        info_label.setStyleSheet("font-size: 9pt; color: grey;")
        self.layout.addWidget(info_label, 0, Qt.AlignmentFlag.AlignCenter)

    def _on_homepage_changed(self):
        self.main_window.settings.setValue("homepage", self.homepage_edit.text())

    def _on_search_engine_changed(self):
        self.main_window.settings.setValue("search_engine", self.search_engine_edit.text())

    def _on_block_list_changed(self):
        text = self.block_list_edit.toPlainText()
        self.main_window._update_user_block_list(text)

class AboutDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Acerca de Wemphix"))
        self.setMinimumWidth(450)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        header_layout = QVBoxLayout()
        header_layout.setSpacing(5)
        
        title_label = QLabel("Wemphix") # El nombre no se traduce
        font = title_label.font()
        font.setPointSize(20)
        font.setBold(True)
        title_label.setFont(font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc_label = QLabel(self.tr("Un navegador web ligero, rápido y de código abierto."))
        desc_font = desc_label.font()
        desc_font.setPointSize(11)
        desc_label.setFont(desc_font)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        palette = self.palette()
        secondary_color = palette.color(QPalette.ColorRole.PlaceholderText).name()
        desc_label.setStyleSheet(f"color: {secondary_color};")

        header_layout.addWidget(title_label)
        header_layout.addWidget(desc_label)
        layout.addLayout(header_layout)

        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        browser_version = "1.3" 
        qt_version_str = qVersion()
        
        form_layout.addRow(self.tr("Versión del Navegador:"), QLabel(browser_version))
        form_layout.addRow(self.tr("Motor de Renderizado:"), QLabel("QtWebEngine (basado en Chromium)"))
        form_layout.addRow(self.tr("Versión de Qt:"), QLabel(qt_version_str))
        
        source_code_label = QLabel('<a href="https://github.com/WemphixOrg">github.com/WemphixOrg</a>')
        source_code_label.setOpenExternalLinks(True)
        form_layout.addRow(self.tr("Código Fuente:"), source_code_label)

        profile_path = parent.profile_path
        if profile_path:
            profile_widget = QWidget()
            profile_layout = QHBoxLayout(profile_widget)
            profile_layout.setContentsMargins(0,0,0,0)
            
            profile_path_label = QLabel(profile_path)
            profile_path_label.setWordWrap(True)
            
            open_folder_btn = QPushButton(self.tr("Abrir"))
            open_folder_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(profile_path)))
            
            profile_layout.addWidget(profile_path_label, 1)
            profile_layout.addWidget(open_folder_btn)
            form_layout.addRow(self.tr("Ruta del Perfil:"), profile_widget)

        layout.addLayout(form_layout)
        
        # Close button
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(self.accept)
        button_box.setCenterButtons(True)
        layout.addWidget(button_box)

class StreamingDiagnosticsDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Diagnóstico de Streaming")
        self.setMinimumWidth(600)

        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(15)
        self.layout.setContentsMargins(15, 15, 15, 15)

        drm_group = QGroupBox("Paso 1: DRM para Contenido Protegido (Widevine)")
        drm_layout = QVBoxLayout(drm_group)
        self.drm_status_label = QLabel("<b>Estado:</b> Comprobando...")
        drm_layout.addWidget(self.drm_status_label)
        self.drm_info_label = QLabel()
        self.drm_info_label.setWordWrap(True)
        drm_layout.addWidget(self.drm_info_label)
        self.drm_action_button = QPushButton()
        self.drm_action_button.setVisible(False)
        drm_layout.addWidget(self.drm_action_button)
        self.layout.addWidget(drm_group)
        self.check_widevine()

        codec_group = QGroupBox("Paso 2: Códecs para Streaming (H.264)")
        codec_layout = QVBoxLayout(codec_group)
        self.codec_status_label = QLabel("<b>Estado:</b> Comprobando...")
        codec_layout.addWidget(self.codec_status_label)
        self.codec_info_label = QLabel()
        self.codec_info_label.setWordWrap(True)
        self.codec_info_label.setTextFormat(Qt.TextFormat.RichText)
        self.codec_info_label.setOpenExternalLinks(True)
        codec_layout.addWidget(self.codec_info_label)
        self.layout.addWidget(codec_group)
        self.check_codecs()

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(self.accept)
        self.layout.addWidget(button_box)

    def check_widevine(self):
        base_path = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
        self.widevine_target_path = os.path.join(base_path, "WidevineCdm")

        if os.path.exists(self.widevine_target_path):
            self.drm_status_label.setText("<b>Estado:</b> <span style='color:green;'>INSTALADO</span> ✅")
            self.drm_info_label.setText("El módulo para contenido protegido (como Netflix) ya está en su sitio.")
            return

        potential_sources = []
        for path in [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")]:
            if path:
                potential_sources.append(os.path.join(path, "Google", "Chrome", "Application"))
                potential_sources.append(os.path.join(path, "Microsoft", "Edge", "Application"))
        
        self.found_source = next((os.path.join(source, item, "WidevineCdm") for source in potential_sources if os.path.exists(source) for item in os.listdir(source) if item.replace('.', '').isdigit() and os.path.exists(os.path.join(source, item, "WidevineCdm"))), None)

        if self.found_source:
            source_browser = "Google Chrome" if "chrome" in self.found_source.lower() else "Microsoft Edge"
            self.drm_status_label.setText("<b>Estado:</b> <span style='color:orange;'>NO INSTALADO (Solución disponible)</span> ⚠️")
            self.drm_info_label.setText(f"Se ha encontrado el módulo en tu instalación de <b>{source_browser}</b>. Puedes copiarlo automáticamente.")
            self.drm_action_button.setText(f"Copiar desde {source_browser}")
            self.drm_action_button.setVisible(True)
            self.drm_action_button.clicked.connect(self.copy_widevine)
        else:
            self.drm_status_label.setText("<b>Estado:</b> <span style='color:red;'>NO ENCONTRADO</span> ❌")
            self.drm_info_label.setText(f"No se encontró Widevine. Deberás copiar la carpeta '<b>WidevineCdm</b>' manualmente desde Chrome/Edge a la carpeta de Wemphix:<br><pre>{base_path}</pre>")

    def check_codecs(self):
        has_codecs = False
        try:
            
            has_codecs = QWebEngineProfile.isFeatureSupported(QWebEngineProfile.Feature.ProprietaryVideoCodecs)
        except AttributeError:
            pass

        if has_codecs:
            self.codec_status_label.setText("<b>Estado:</b> <span style='color:green;'>COMPATIBLE</span> ✅")
            self.codec_info_label.setText("Tu navegador es compatible con los códecs de video modernos (H.264). El streaming en sitios como YouTube debería funcionar.")
        else:
            self.codec_status_label.setText("<b>Estado:</b> <span style='color:red;'>NO COMPATIBLE</span> ❌")
            self.codec_info_label.setText(
                """
                <p>A tu navegador le faltan los códecs de video esenciales (H.264), por eso algunos sitios de streaming no funcionan.</p>
                <p>Por temas de licencia, la versión estándar del motor web no los incluye.</p>
                <hr>
                <b>SOLUCIÓN DEFINITIVA:</b>
                <p>Para instalar la versión completa del motor web con todos los códecs, cierra el navegador y ejecuta el siguiente comando en tu terminal (cmd/PowerShell):</p>
                <pre style="background-color:#f0f0f0; color:#000000; padding:10px; border-radius:3px;">pip install --upgrade --force-reinstall --index-url https://www.riverbankcomputing.com/pypi/gpl/ PyQt6-WebEngine</pre>
                <p>Después de ejecutarlo, vuelve a iniciar Wemphix. El problema de streaming estará resuelto.</p>
                """
            )

    def copy_widevine(self):
        try:
            shutil.copytree(self.found_source, self.widevine_target_path)
            QMessageBox.information(self, "Éxito", "Módulo DRM copiado. Por favor, reinicia Wemphix para que los cambios surtan efecto.")
            QApplication.instance().quit()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo copiar el módulo DRM:\n{e}")

class BookmarkManager:
    """Encapsulates all logic for managing bookmarks."""
    def __init__(self, bookmarks_path, bookmarks_widget: QListWidget):
        self.path = bookmarks_path
        self.widget = bookmarks_widget
        self.bookmarks = []
        self.load()

    def load(self):
        """Loads bookmarks from the JSON file."""
        if not self.path or not os.path.exists(self.path):
            self.bookmarks = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.bookmarks = json.load(f)
        except (json.JSONDecodeError, IOError):
            print("Error al cargar los favoritos. Se iniciará con una lista vacía.")
            self.bookmarks = []
        self.populate_widget()

    def save(self):
        """Saves the current list of bookmarks to the JSON file."""
        if not self.path:
            return
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.bookmarks, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"No se pudieron guardar los favoritos: {e}")

    def add(self, title, url) -> bool:
        """Adds a new bookmark. Returns True on success, False if it already exists."""
        if self.is_bookmarked(url):
            return False
        
        self.bookmarks.append({'title': title, 'url': url})
        self.save()
        self._add_item_to_widget({'title': title, 'url': url})
        return True

    def delete(self, urls_to_delete: set) -> bool:
        """Deletes bookmarks based on a set of URLs. Returns True if any were deleted."""
        initial_count = len(self.bookmarks)
        self.bookmarks = [bm for bm in self.bookmarks if bm.get('url') not in urls_to_delete]
        
        if len(self.bookmarks) < initial_count:
            self.save()
            self.populate_widget()
            return True
        return False

    def is_bookmarked(self, url: str) -> bool:
        """Checks if a URL is already in the bookmarks."""
        return any(bookmark.get('url') == url for bookmark in self.bookmarks)

    def populate_widget(self):
        """Clears and repopulates the QListWidget with current bookmarks."""
        if not self.widget:
            return
        self.widget.clear()
        for bookmark in self.bookmarks:
            self._add_item_to_widget(bookmark)
    
    def _add_item_to_widget(self, bookmark):
        """Adds a single bookmark item to the QListWidget."""
        if not self.widget: return
        item = QListWidgetItem(bookmark['title'])
        item.setData(Qt.ItemDataRole.UserRole, bookmark['url'])
        self.widget.addItem(item)

class Navegador(QMainWindow):
    def __init__(self, is_incognito=False, main_window=None):
        super().__init__()
        self.is_incognito = is_incognito
        self.main_window = main_window
        self.other_windows = []
        self.profile_path = ""
        self.session_path = ""
        self.about_to_clear_profile = False
        self.battery_saver_enabled = False
        self.super_memory_saver_enabled = False
        
        self._screenshot_parts = []
        self._screenshot_webview = None
        self._screenshot_initial_scroll = QPoint(0, 0)
        self._screenshot_total_height = 0
        self._screenshot_view_height = 0
        self.bookmarks_dock = None
        self.bookmark_manager = None
        self.bookmarks_list_widget = None
        self.downloads_dock = None
        self.downloads_table = None
        self.downloads = {}
        self.history_dock = None
        self.history_list_widget = None
        self.history_path = ""
        self.history = []
        self.notes_dock = None
        self.notes_editor = None
        self.notes_path = ""
        self.extensions_path = ""
        self.background_pages = {}
        self.extensions_manifest_path = ""
        self.extensions = {}
        self.browser_api = BrowserApi(self)
        self.ad_blocker = AdBlockInterceptor()
        self.qwebchannel_script_content = ""
        self.password_manager = None
        self.password_handler_script_content = ""
        self.last_app_state = Qt.ApplicationState.ApplicationActive
        self.settings = QSettings("WemphixOrg", "Wemphix")

        self.rgb_theme_timer = QTimer(self)
        self.rgb_theme_timer.timeout.connect(self._update_rgb_theme)
        self.rgb_hue = 0

        self.suggestion_timer = QTimer(self)
        self.suggestion_timer.setSingleShot(True)
        self.suggestion_timer.setInterval(250)
        self.suggestion_timer.timeout.connect(self._perform_url_suggestions)

        self.threadpool = QThreadPool()
        print(f"INFO: Thread pool started with {self.threadpool.maxThreadCount()} threads.")

        self.battery_saver_enabled = self.settings.value("batterySaverEnabled", False, type=bool)
        self.super_memory_saver_enabled = self.settings.value("superMemorySaverEnabled", False, type=bool)

        self._setup_profile()
        self._load_qwebchannel_script()
        self._load_password_handler_script()
        self._setup_adblocker()
        self.persistent_profile.setUrlRequestInterceptor(self.ad_blocker)
        self._load_user_block_list()
        self._load_extensions()
        self._load_history()
        self._load_notes()
        self._setup_ui()
        self._setup_password_manager()
        self._setup_shortcuts()
        
        custom_theme = self.settings.value("custom_theme", "Default")
        custom_color = self.settings.value("custom_theme_color", None)
        self.apply_custom_theme(custom_theme, custom_color)
        self._create_menu()
        
        self.restoreGeometry(self.settings.value("geometry", self.saveGeometry()))
        self.restoreState(self.settings.value("windowState", self.saveState()))

        self._restore_session()

    def _setup_profile(self):
        if self.is_incognito:
            self.persistent_profile = QWebEngineProfile(self)
            self.setWindowTitle("Wemphix (Incógnito)")
            self.bookmarks_path = ""
            self.passwords_path = ""
            self.history_path = ""
        else:
            self.profile_path = os.path.join(os.path.expanduser("~"), "Wemphix")
            profile_data_path = os.path.join(self.profile_path, "ProfileData")
            self.bookmarks_path = os.path.join(self.profile_path, "bookmarks.json")
            self.history_path = os.path.join(self.profile_path, "history.json")
            self.extensions_path = os.path.join(self.profile_path, "extensions")
            self.session_path = os.path.join(self.profile_path, "session.json")
            self.notes_path = os.path.join(self.profile_path, "notes.txt")
            self.passwords_path = os.path.join(self.profile_path, "passwords.json.enc")
            self.extensions_manifest_path = os.path.join(self.extensions_path, "extensions.json")
            os.makedirs(self.extensions_path, exist_ok=True)
            os.makedirs(self.profile_path, exist_ok=True)

            self.persistent_profile = QWebEngineProfile("Profile_user", self)
            self.persistent_profile.setPersistentStoragePath(profile_data_path)
            self.persistent_profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)

        self.persistent_profile.downloadRequested.connect(self._handle_download_request)

    def _load_qwebchannel_script(self):
        """Carga el contenido de qwebchannel.js en memoria al inicio para acelerar la creación de pestañas."""
        if self.is_incognito:
            return
        
        qwebchannel_path = get_asset_path("qwebchannel.js")
        if os.path.exists(qwebchannel_path):
            try:
                with open(qwebchannel_path, "r", encoding="utf-8") as f:
                    self.qwebchannel_script_content = f.read()
            except IOError as e:
                print(f"ERROR: No se pudo leer 'qwebchannel.js': {e}")
        else:
            print("ADVERTENCIA: No se encontró 'qwebchannel.js'. La API de extensiones no funcionará.")

    def _load_password_handler_script(self):
        """Carga el script de manejo de contraseñas en memoria."""
        if self.is_incognito:
            return
        
        script_path = get_asset_path("password_handler.js")
        if os.path.exists(script_path):
            try:
                with open(script_path, "r", encoding="utf-8") as f:
                    self.password_handler_script_content = f.read()
            except IOError as e:
                print(f"ERROR: No se pudo leer 'password_handler.js': {e}")
        else:
            print("ADVERTENCIA: No se encontró 'password_handler.js'. La gestión de contraseñas no funcionará.")

    def _setup_adblocker(self):
        self.adblock_list_path = os.path.join(self.profile_path, "adblock_list.txt")
        self.ad_blocker.load_ad_block_list(self.adblock_list_path)

    def _load_user_block_list(self):
        user_list_text = self.settings.value("user_block_list", "")
        self.ad_blocker.update_user_block_list(user_list_text)

    def _setup_ui(self):
        self.setWindowTitle("Wemphix")
        self.setGeometry(100, 100, 1300, 900)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.cerrar_pestana)
        self.setCentralWidget(self.tabs)
        self.tabs.currentChanged.connect(self._on_tab_activated)
        self.tabs.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabs.customContextMenuRequested.connect(self._show_tab_context_menu)
        self.tabs.setUsesScrollButtons(True)

        corner_widget = QWidget()
        corner_layout = QHBoxLayout(corner_widget)
        corner_layout.setContentsMargins(2, 0, 2, 0)
        corner_layout.setSpacing(2)

        search_tabs_btn = QPushButton("▼")
        search_tabs_btn.setToolTip("Buscar pestañas (Ctrl+Shift+A)")
        search_tabs_btn.setFixedSize(30, 28)
        search_tabs_btn.clicked.connect(self._open_tab_search)

        corner_layout.addWidget(search_tabs_btn)
        corner_layout.addWidget(self.nueva_pestana_btn())
        self.tabs.setCornerWidget(corner_widget)
        self.setStatusBar(QStatusBar())

    def _setup_password_manager(self):
        """Initializes the password manager to a locked state (None)."""
        self.password_manager = None
        if self.is_incognito:
            return

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+T"), self, lambda: self.agregar_pestana(focus=True))
        QShortcut(QKeySequence("Ctrl+W"), self, lambda: self.cerrar_pestana(self.tabs.currentIndex()))
        QShortcut(QKeySequence("Ctrl+R"), self, self._reload_current_tab)
        QShortcut(QKeySequence("Ctrl+F"), self, self._show_find_bar)
        QShortcut(QKeySequence("F5"), self, self._reload_current_tab)
        QShortcut(QKeySequence("Ctrl+L"), self, self._focus_url_bar)
        QShortcut(QKeySequence("Alt+D"), self, self._focus_url_bar)
        QShortcut(QKeySequence("Ctrl++"), self, self._zoom_in)
        QShortcut(QKeySequence("Ctrl+-"), self, self._zoom_out)
        QShortcut(QKeySequence("Ctrl+0"), self, self._reset_zoom)
        QShortcut(QKeySequence("Ctrl+Shift+A"), self, self._open_tab_search)

    def _reload_current_tab(self):
        if webview := self._get_current_webview():
            webview.reload()

    def _show_find_bar(self):
        if current_widget := self.tabs.currentWidget():
            find_bar = current_widget.findChild(QWidget, "find_bar")
            find_input = find_bar.findChild(QLineEdit, "find_input")
            find_bar.setVisible(not find_bar.isVisible())
            find_input.setFocus()
            find_input.selectAll()

    def _focus_url_bar(self):
        if (current_widget := self.tabs.currentWidget()) and (url_bar := current_widget.findChild(QLineEdit)):
            url_bar.setFocus()
            url_bar.selectAll()

    def _get_current_webview(self) -> QWebEngineView | None:
        if current_widget := self.tabs.currentWidget():
            return current_widget.findChild(QWebEngineView)
        return None

    def _on_tab_activated(self, index):
        if widget := self.tabs.widget(index):
            tab_id = widget.property("tab_id")
            self.browser_api.onTabActivated.emit(tab_id)

            is_readable = widget.property("is_readable") or False
            in_reader_mode = widget.property("in_reader_mode") or False
            if hasattr(self, 'reader_mode_action'):
                self.reader_mode_action.setEnabled(is_readable or in_reader_mode)
                self.reader_mode_action.setChecked(in_reader_mode)


            if self.settings.value("custom_theme") == "Adaptativo":
                dominant_color = widget.property("dominant_color")
                if dominant_color:
                    self.apply_custom_theme("Custom", dominant_color)
                else:
                    self.apply_custom_theme("Default")

    def _perform_url_suggestions(self):
        """Ejecuta la lógica de autocompletado después de una breve pausa."""
        if (current_widget := self.tabs.currentWidget()) and \
           (url_bar := current_widget.findChild(QLineEdit)) and \
           (completer := url_bar.completer()):
            model = completer.model()
            self._update_url_suggestions(url_bar.text(), model)

    def _get_current_tab_widget(self) -> QWidget | None:
        if self.tabs:
            return self.tabs.currentWidget()
        return None

    def _create_menu(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu(self.tr("&Archivo"))

        new_incognito_action = file_menu.addAction(self.tr("Nueva ventana de incógnito"))
        new_incognito_action.setShortcut("Ctrl+Shift+N")
        new_incognito_action.triggered.connect(self._open_incognito_window)
        file_menu.addSeparator()

        import_action = file_menu.addAction(self.tr("Importar datos..."))
        import_action.triggered.connect(lambda: self._handle_import_export(is_import=True))
        export_action = file_menu.addAction(self.tr("Exportar datos..."))
        export_action.triggered.connect(lambda: self._handle_import_export(is_import=False))
        if self.is_incognito:
            import_action.setEnabled(False)
            export_action.setEnabled(False)
        file_menu.addSeparator()

        battery_saver_action = file_menu.addAction(self.tr("Ahorro de batería"))
        battery_saver_action.setCheckable(True)
        battery_saver_action.setChecked(self.battery_saver_enabled)
        battery_saver_action.toggled.connect(self._toggle_battery_saver)

        super_saver_action = file_menu.addAction(self.tr("Ahorro de memoria extremo"))
        super_saver_action.setCheckable(True)
        super_saver_action.setChecked(self.super_memory_saver_enabled)
        super_saver_action.toggled.connect(self._toggle_super_memory_saver)

        file_menu.addSeparator()
        clear_action = file_menu.addAction(self.tr("Limpiar perfil y salir"))
        clear_action.triggered.connect(self.solicitar_limpiar_perfil)
        if self.is_incognito:
            clear_action.setEnabled(False)

        view_menu = menu_bar.addMenu(self.tr("&Ver"))
        toggle_bookmarks_action = view_menu.addAction(self.tr("Panel de Favoritos"))
        toggle_bookmarks_action.setCheckable(True)
        toggle_bookmarks_action.setChecked(self.bookmarks_dock.isVisible() if self.bookmarks_dock else False)
        toggle_bookmarks_action.triggered.connect(self._toggle_bookmarks_dock)
        toggle_downloads_action = view_menu.addAction(self.tr("Panel de Descargas"))
        toggle_downloads_action.setCheckable(True)
        toggle_downloads_action.setChecked(self.downloads_dock.isVisible() if self.downloads_dock else False)
        toggle_downloads_action.triggered.connect(self._toggle_downloads_dock)
        toggle_history_action = view_menu.addAction(self.tr("Panel de Historial"))
        toggle_history_action.setCheckable(True)
        toggle_history_action.setChecked(self.history_dock.isVisible() if self.history_dock else False)
        toggle_history_action.triggered.connect(self._toggle_history_dock)

        toggle_notes_action = view_menu.addAction(self.tr("Panel de Notas"))
        toggle_notes_action.setCheckable(True)
        toggle_notes_action.setChecked(self.notes_dock.isVisible() if self.notes_dock else False)
        toggle_notes_action.triggered.connect(self._toggle_notes_dock)
        
        view_menu.addSeparator()
        self.reader_mode_action = view_menu.addAction(self.tr("Modo Lectura"))
        self.reader_mode_action.setCheckable(True)
        self.reader_mode_action.setEnabled(False)
        self.reader_mode_action.triggered.connect(self._toggle_reader_mode)
        view_menu.addSeparator()

        zoom_in_action = view_menu.addAction(self.tr("Acercar"))
        zoom_in_action.setShortcut("Ctrl++")
        zoom_in_action.triggered.connect(self._zoom_in)
        zoom_out_action = view_menu.addAction(self.tr("Alejar"))
        zoom_out_action.setShortcut("Ctrl+-")
        zoom_out_action.triggered.connect(self._zoom_out)
        reset_zoom_action = view_menu.addAction(self.tr("Restablecer Zoom"))
        reset_zoom_action.setShortcut("Ctrl+0")
        reset_zoom_action.triggered.connect(self._reset_zoom)

        tools_menu = menu_bar.addMenu(self.tr("&Herramientas"))
        toggle_adblock_action = tools_menu.addAction(self.tr("Activar Bloqueador de Anuncios"))
        toggle_adblock_action.setCheckable(True)
        toggle_adblock_action.setChecked(True)
        toggle_adblock_action.toggled.connect(self.ad_blocker.setEnabled)
        tools_menu.addSeparator()
        self.update_adblock_action = tools_menu.addAction(self.tr("Actualizar Lista de Bloqueo"))
        self.update_adblock_action.triggered.connect(self._update_blocklist)
        tools_menu.addSeparator()
        clear_data_action = tools_menu.addAction(self.tr("Limpiar datos de navegación..."))
        clear_data_action.triggered.connect(self._clear_browsing_data)

        site_permissions_action = tools_menu.addAction(self.tr("Permisos de sitios..."))
        site_permissions_action.triggered.connect(self._open_site_permissions_dialog)
        if self.is_incognito:
            site_permissions_action.setEnabled(False)

        tools_menu.addSeparator()
        screenshot_menu = tools_menu.addMenu(self.tr("Captura de Pantalla"))
        visible_area_action = screenshot_menu.addAction(self.tr("Capturar área visible"))
        visible_area_action.triggered.connect(self._capture_visible_area)
        full_page_action = screenshot_menu.addAction(self.tr("Capturar página completa"))
        full_page_action.triggered.connect(self._capture_full_page)

        tools_menu.addSeparator()
        manage_extensions_action = tools_menu.addAction(self.tr("Gestionar Extensiones..."))
        manage_extensions_action.triggered.connect(self._manage_extensions)
        tools_menu.addSeparator()
        
        manage_passwords_action = tools_menu.addAction(self.tr("Gestionar Contraseñas..."))
        manage_passwords_action.triggered.connect(self._manage_passwords)
        if self.is_incognito:
            manage_passwords_action.setEnabled(False)

        tools_menu.addSeparator()

        open_profile_action = tools_menu.addAction(self.tr("Abrir carpeta del perfil"))
        open_profile_action.setToolTip(self.tr("Abre la carpeta donde se guardan los datos del navegador (historial, favoritos, etc.)"))
        open_profile_action.triggered.connect(self._open_profile_folder)
        if self.is_incognito:
            open_profile_action.setEnabled(False)

        ua_menu = tools_menu.addMenu(self.tr("User-Agent"))
        self.user_agent_group = QActionGroup(self)
        self.user_agent_group.setExclusive(True)
        
        default_ua_action = ua_menu.addAction(self.tr("Default (Wemphix)"))
        default_ua_action.setCheckable(True)
        default_ua_action.setChecked(True)
        default_ua_action.triggered.connect(lambda: self._set_user_agent(None))
        self.user_agent_group.addAction(default_ua_action)

        chrome_ua_action = ua_menu.addAction(self.tr("Chrome (Windows)"))
        chrome_ua_action.setCheckable(True)
        chrome_ua_action.triggered.connect(lambda: self._set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"))
        self.user_agent_group.addAction(chrome_ua_action)

        help_menu = menu_bar.addMenu(self.tr("A&yuda"))
        about_action = help_menu.addAction(self.tr("&Acerca de..."))
        about_action.triggered.connect(self.mostrar_acerca_de)
        help_menu.addSeparator()
        diag_action = help_menu.addAction(self.tr("Diagnóstico de Streaming"))
        diag_action.triggered.connect(self._run_streaming_diagnostics)

    def nueva_pestana_btn(self):
        btn = QPushButton("+")
        btn.setFixedSize(30, 28)
        btn.setToolTip("Nueva pestaña (Ctrl+T)")
        btn.clicked.connect(lambda: self.agregar_pestana())
        return btn

    def agregar_pestana(self, url="https://www.google.com", focus=True):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        nav_bar_widget = QWidget()
        nav_bar_widget.setObjectName("NavBarWidget")
        nav_bar = QHBoxLayout(nav_bar_widget)
        nav_bar.setContentsMargins(4, 4, 4, 4)
        nav_bar.setSpacing(4)
        url_bar = QLineEdit()
        url_bar.setPlaceholderText("Escribe una URL o busca...")

        completer_model = QStringListModel(url_bar)
        url_completer = QCompleter(completer_model, url_bar)
        url_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        url_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        url_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        url_bar.setCompleter(url_completer)

        url_bar.textChanged.connect(self.suggestion_timer.start)

        style = self.style()
        atras_btn = QPushButton()
        atras_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        atras_btn.setObjectName("atras_btn")
        atras_btn.setFixedSize(28, 28)
        atras_btn.setEnabled(False)
        adelante_btn = QPushButton()
        adelante_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward))
        adelante_btn.setObjectName("adelante_btn")
        adelante_btn.setFixedSize(28, 28)
        adelante_btn.setEnabled(False)
        recargar_btn = QPushButton()
        recargar_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        recargar_btn.setFixedSize(28, 28)
        home_btn = QPushButton()
        home_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        home_btn.setToolTip("Ir a la página de inicio")
        home_btn.setFixedSize(28, 28)

        add_bookmark_btn = QPushButton()
        add_bookmark_btn.setObjectName("add_bookmark_btn")
        add_bookmark_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        add_bookmark_btn.setToolTip("Añadir esta página a Favoritos")
        add_bookmark_btn.setFixedSize(28, 28)
        downloads_btn = QPushButton()
        downloads_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        downloads_btn.setToolTip("Abrir carpeta de descargas")
        downloads_btn.setFixedSize(28, 28)
        settings_btn = QPushButton()
        settings_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        settings_btn.setToolTip("Configuración")
        settings_btn.setFixedSize(28, 28)
        personalize_btn = QPushButton()
        personalize_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogListView))
        personalize_btn.setToolTip("Personalizar apariencia")
        personalize_btn.setFixedSize(28, 28)

        nav_bar.addWidget(atras_btn)
        nav_bar.addWidget(adelante_btn)
        nav_bar.addWidget(recargar_btn)
        nav_bar.addWidget(home_btn)
        nav_bar.addWidget(url_bar, 1)
        
        reader_mode_btn = QPushButton("📖")
        reader_mode_btn.setObjectName("reader_mode_btn")
        reader_mode_btn.setToolTip("Entrar en Modo Lectura")
        reader_mode_btn.setFixedSize(28, 28)
        reader_mode_btn.setVisible(False)
        reader_mode_btn.clicked.connect(self._toggle_reader_mode)
        nav_bar.addWidget(reader_mode_btn)

        nav_bar.addWidget(add_bookmark_btn)
        
        for ext_id, ext_data in self.extensions.items():
            if not ext_data.get("enabled", False): continue
            manifest = ext_data.get("manifest", {})
            if "browser_action" in manifest:
                action_btn = QPushButton()
                action_btn.setObjectName(f"browser_action_{ext_id}")
                action_btn.setFixedSize(28, 28)
                self._configure_browser_action_button(action_btn, ext_id, manifest["browser_action"])
                action_btn.clicked.connect(lambda checked, e_id=ext_id: self._handle_browser_action_click(e_id))
                nav_bar.addWidget(action_btn)

        nav_bar.addWidget(personalize_btn)
        nav_bar.addWidget(downloads_btn)
        nav_bar.addWidget(settings_btn)
        layout.addWidget(nav_bar_widget)

        content_area = QWidget()
        content_layout = QGridLayout(content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        progress_bar = QProgressBar()
        progress_bar.setFixedHeight(2)
        progress_bar.setTextVisible(False)
        progress_bar.setVisible(False)

        webview = QWebEngineView()
        find_bar = self._create_find_bar()

        content_layout.addWidget(webview, 0, 0)
        content_layout.addWidget(progress_bar, 0, 0, Qt.AlignmentFlag.AlignTop)
        content_layout.addWidget(find_bar, 0, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)

        layout.addWidget(content_area, 1)

        url_completer.activated.connect(lambda text, wv=webview, bar=url_bar: self._suggestion_selected(text, wv, bar))

        page = CustomWebEnginePage(self.persistent_profile, webview)
        page.featurePermissionRequested.connect(self.handle_permission_request)
        page.customDownloadRequested.connect(self._start_custom_download)

        self._setup_page_scripts(page)

        channel = QWebChannel(page)
        page.setWebChannel(channel)
        channel.registerObject("browser_api", self.browser_api)

        self._apply_page_settings(page)

        if hasattr(page, 'isAudibleChanged'):
            page.isAudibleChanged.connect(self._handle_audio_state_change)
        if hasattr(page, 'audioMutedChanged'):
            page.audioMutedChanged.connect(self._handle_audio_state_change)

        webview.setPage(page)
        webview.setUrl(QUrl(url))

        atras_btn.clicked.connect(webview.back)
        home_btn.clicked.connect(self._go_home)

        url_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        url_bar.customContextMenuRequested.connect(lambda point, bar=url_bar, wv=webview: self._show_url_bar_context_menu(point, bar, wv))

        adelante_btn.clicked.connect(webview.forward)
        recargar_btn.clicked.connect(webview.reload)
        url_bar.returnPressed.connect(lambda: self.navegar(webview, url_bar))
        add_bookmark_btn.clicked.connect(self._add_current_page_to_bookmarks)
        downloads_btn.clicked.connect(self._open_downloads_folder)
        settings_btn.clicked.connect(self._open_settings_dialog)
        personalize_btn.clicked.connect(self._open_personalization_dialog)

        webview.loadStarted.connect(lambda: progress_bar.setVisible(True))
        webview.loadProgress.connect(progress_bar.setValue)
        webview.loadFinished.connect(lambda: progress_bar.setVisible(False))

        webview.loadFinished.connect(lambda ok, webview=webview: self._on_page_load_finished(ok, webview))
        webview.loadFinished.connect(self.actualizar_estado_botones_nav)
        webview.urlChanged.connect(self.actualizar_ui_pestana)

        index = self.tabs.addTab(tab, "Nueva Pestaña")
        tab.setProperty("tab_id", str(uuid.uuid4()))
        if focus:
            self.tabs.setCurrentIndex(index)

        if not self.is_incognito:
            self.browser_api.tabAdded.emit({"index": index, "title": "Nueva Pestaña", "url": url})

        webview.titleChanged.connect(self.actualizar_titulo_pestana)
        webview.iconChanged.connect(self.actualizar_icono_pestana)

        return webview

    def _configure_browser_action_button(self, button: QPushButton, ext_id: str, action_info: dict):
        icon_path_str = action_info.get("default_icon")
        if icon_path_str:
            icon_path = os.path.join(self.extensions_path, ext_id, icon_path_str)
            if os.path.exists(icon_path):
                button.setIcon(QIcon(icon_path))
        
        title = action_info.get("default_title", "")
        if title:
            button.setToolTip(title)

    def _create_find_bar(self):
        find_bar = QFrame()
        find_bar.setObjectName("find_bar")
        find_bar.setFrameShape(QFrame.Shape.StyledPanel)
        find_bar.setStyleSheet("""
            #find_bar {
                background-color: rgba(240, 240, 240, 0.95);
                border: 1px solid #c0c0c0;
                border-radius: 8px;
                margin: 8px;
            }
            Q[theme="Oscuro"] #find_bar {
                background-color: rgba(45, 45, 45, 0.95);
                border: 1px solid #555;
            }
        """)
        find_bar.setMaximumWidth(350)
        find_layout = QHBoxLayout(find_bar)
        find_layout.setContentsMargins(5, 2, 5, 2)

        find_input = QLineEdit()
        find_input.setPlaceholderText("Buscar en la página...")
        find_input.setObjectName("find_input")
        
        find_results_label = QLabel("0/0")
        find_results_label.setObjectName("find_results_label")

        prev_btn = QPushButton("<")
        prev_btn.setObjectName("find_prev_btn")
        prev_btn.setFixedSize(24, 24)
        next_btn = QPushButton(">")
        next_btn.setObjectName("find_next_btn")
        next_btn.setFixedSize(24, 24)
        close_btn = QPushButton("×")
        close_btn.setObjectName("find_close_btn")
        close_btn.setFixedSize(24, 24)

        find_layout.addWidget(find_input)
        find_layout.addWidget(find_results_label)
        find_layout.addWidget(prev_btn)
        find_layout.addWidget(next_btn)
        find_layout.addWidget(close_btn)
        find_bar.setVisible(False)

        close_btn.clicked.connect(lambda: find_bar.setVisible(False))

        return find_bar

    def _on_page_load_finished(self, ok, webview):
        """
        Centraliza las acciones que ocurren cuando una página termina de cargar.
        """
        if not ok:
            return

        self._add_to_history(ok, webview)
        self._check_for_readable_content(webview)

        find_bar = webview.parentWidget().findChild(QWidget, "find_bar")
        if find_bar:
            find_input = find_bar.findChild(QLineEdit, "find_input")
            find_results_label = find_bar.findChild(QLabel, "find_results_label")
            prev_btn = find_bar.findChild(QPushButton, "find_prev_btn")
            next_btn = find_bar.findChild(QPushButton, "find_next_btn")

            if all((find_input, find_results_label, prev_btn, next_btn)):
                find_input.textChanged.connect(lambda text, wv=webview: self._find_text(text, wv))
                prev_btn.clicked.connect(lambda wv=webview: self._find_previous(wv))
                next_btn.clicked.connect(lambda wv=webview: self._find_next(wv))
                find_input.returnPressed.connect(next_btn.click)
                webview.page().findTextFinished.connect(lambda result, label=find_results_label: self._update_find_results(result, label))

    def navegar(self, webview, url_bar):
        url = url_bar.text()
        parsed_url = urlparse(url)

        if not parsed_url.scheme and '.' not in parsed_url.path:
            search_engine = self.settings.value("search_engine", "https://www.google.com/search?q={}")
            search_url = search_engine.format(quote_plus(url))
            webview.setUrl(QUrl(search_url))
        else:
            if not parsed_url.scheme:
                url = "https://" + url
            webview.setUrl(QUrl(url))

    def _set_user_agent(self, user_agent):
        self.persistent_profile.setHttpUserAgent(user_agent)
        QMessageBox.information(self, "User-Agent Cambiado", "El User-Agent ha sido actualizado. Recarga las pestañas para aplicar el cambio.")

    def _open_incognito_window(self):
        main_win = self.main_window if self.main_window else self
        incognito_window = Navegador(is_incognito=True, main_window=main_win)
        main_win.other_windows.append(incognito_window)
        incognito_window.show()

    def _clear_browsing_data(self):
        if self.is_incognito:
            QMessageBox.information(self, "Modo Incógnito", "Los datos de navegación no se guardan en este modo.")
            return

        reply = QMessageBox.question(self, 'Limpiar Datos',
                                     "¿Estás seguro de que quieres borrar las cookies y la caché?\nEsto puede cerrar la sesión en algunos sitios web.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            self.persistent_profile.clearHttpCache()
            self.persistent_profile.cookieStore().deleteAllCookies()
            QMessageBox.information(self, "Datos Limpiados", "La caché y las cookies han sido borradas.")

    def closeEvent(self, event):
        self._stop_rgb_theme()
        if not self.is_incognito:
            self.settings.setValue("geometry", self.saveGeometry())
            self.settings.setValue("windowState", self.saveState())
            self._save_session()
            self._save_history()
            self._save_notes()
            for window in list(self.other_windows):
                window.close()
        elif self.main_window and self in self.main_window.other_windows:
            self.main_window.other_windows.remove(self)

        for i in range(self.tabs.count()):
            if widget := self.tabs.widget(i):
                if webview := widget.findChild(QWebEngineView):
                    webview.setPage(None)
        self.tabs.clear()

        for page in self.background_pages.values():
            page.deleteLater()
        self.background_pages.clear()

        super().closeEvent(event)

    def _open_settings_dialog(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def _open_site_permissions_dialog(self):
        dialog = SitePermissionsDialog(self)
        dialog.exec()

    def _open_personalization_dialog(self):
        dialog = PersonalizationDialog(self)
        dialog.exec()

    def _open_tab_search(self):
        dialog = TabSearchDialog(self)
        dialog.exec()

    def _manage_passwords(self, show_manager_on_success=True):
        """
        Asegura que la bóveda esté lista (desbloqueada o creada) y opcionalmente
        muestra el diálogo de gestión. Devuelve True si la bóveda está lista, False si no.
        """
        if self.password_manager:
            if show_manager_on_success:
                dialog = ManagePasswordsDialog(self)
                dialog.exec()
            return True

        if os.path.exists(self.passwords_path):
            dialog = MasterPasswordDialog(self, is_creating=False)
            if dialog.exec():
                try:
                    self.password_manager = PasswordManager(self.passwords_path, dialog.get_password())
                    self.statusBar().showMessage("Bóveda de contraseñas desbloqueada.", 3000)
                    if show_manager_on_success:
                        ManagePasswordsDialog(self).exec()
                    return True
                except (InvalidToken, ValueError):
                    QMessageBox.critical(self, "Error de Contraseña", "La contraseña maestra es incorrecta.")
        else:
            reply = QMessageBox.question(self, "Crear Bóveda de Contraseñas", "No se encontró una bóveda de contraseñas. ¿Deseas crear una ahora para guardar tus contraseñas de forma segura?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                dialog = MasterPasswordDialog(self, is_creating=True)
                if dialog.exec():
                    self.password_manager = PasswordManager.create_new_vault(self.passwords_path, dialog.get_password())
                    self.statusBar().showMessage("Bóveda de contraseñas creada y desbloqueada.", 3000)
                    if show_manager_on_success:
                        ManagePasswordsDialog(self).exec()
                    return True
        return False

    def _handle_import_export(self, is_import: bool):
        if is_import:
            path, _ = QFileDialog.getOpenFileName(self, "Importar desde archivo", "", "Wemphix Backup (*.json);;Todos los archivos (*)")
            if not path: return

            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                QMessageBox.critical(self, "Error de Lectura", f"No se pudo leer o procesar el archivo de respaldo:\n{e}")
                return

            dialog = DataTransferDialog(self, available_data_keys=data.keys())
            if dialog.exec():
                keys_to_import = dialog.get_selected_keys()
                if "settings" in keys_to_import and "settings" in data:
                    settings_data = data["settings"]
                    for key, value in settings_data.items():
                        self.settings.setValue(key, value)
                    self._load_user_block_list()
                
                if "bookmarks" in keys_to_import and "bookmarks" in data:
                    existing_urls = {bm['url'] for bm in self.bookmark_manager.bookmarks}
                    for bm in data["bookmarks"]:
                        if bm.get('url') not in existing_urls:
                            self.bookmark_manager.bookmarks.append(bm)
                    self.bookmark_manager.save()
                    self.bookmark_manager.populate_widget()

                if "history" in keys_to_import and "history" in data:
                    existing_urls = {h['url'] for h in self.history}
                    for h in data["history"]:
                        if h.get('url') not in existing_urls:
                            self.history.append(h)
                    self._save_history()
                    self._update_history_list_widget()
                
                QMessageBox.information(self, "Importación Completa", "Los datos seleccionados han sido importados.\nAlgunos cambios pueden requerir un reinicio para tener efecto.")

        else: # Export
            dialog = DataTransferDialog(self)
            if dialog.exec():
                keys_to_export = dialog.get_selected_keys()
                if not keys_to_export: return

                path, _ = QFileDialog.getSaveFileName(self, "Exportar a archivo", "wemphix_backup.json", "Wemphix Backup (*.json)")
                if not path: return

                export_data = {}
                if "bookmarks" in keys_to_export: export_data["bookmarks"] = self.bookmark_manager.bookmarks if self.bookmark_manager else []
                if "history" in keys_to_export: export_data["history"] = self.history
                if "settings" in keys_to_export:
                    settings_to_save = ["theme", "homepage", "search_engine", "user_block_list", "batterySaverEnabled", "superMemorySaverEnabled", "custom_theme", "custom_theme_color"]
                    export_data["settings"] = {key: self.settings.value(key) for key in settings_to_save if self.settings.contains(key)}
                
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(export_data, f, indent=4)
                    QMessageBox.information(self, "Exportación Completa", f"Los datos seleccionados se han guardado en:\n{path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error de Escritura", f"No se pudo guardar el archivo de respaldo:\n{e}")

    def _update_url_suggestions(self, text: str, model: QStringListModel):
        """Actualiza las sugerencias para la barra de URL basándose en el historial y los favoritos."""
        if len(text) < 2 or ' ' in text.strip():
            model.setStringList([])
            return

        suggestions = []
        seen_urls = set()
        
        for entry in reversed(self.history):
            if len(suggestions) >= 5: break
            url = entry.get('url', '')
            title = entry.get('title', '')
            if url not in seen_urls and (text.lower() in url.lower() or text.lower() in title.lower()):
                suggestions.append(f" {title} - {url}")
                seen_urls.add(url)

        for bookmark in (self.bookmark_manager.bookmarks if self.bookmark_manager else []):
            if len(suggestions) >= 10: break
            url = bookmark.get('url', '')
            title = bookmark.get('title', '')
            if url not in seen_urls and (text.lower() in url.lower() or text.lower() in title.lower()):
                suggestions.append(f"⭐ {title} - {url}")
                seen_urls.add(url)
        
        model.setStringList(suggestions)

    def _suggestion_selected(self, text: str, webview: QWebEngineView, url_bar: QLineEdit):
        """Navega a la URL de una sugerencia seleccionada."""
        try:
            start_index = max(text.rfind("http://"), text.rfind("https://"))
            if start_index != -1:
                url = text[start_index:]
                url_bar.setText(url)
                webview.setUrl(QUrl(url))
        except (IndexError, ValueError):
            self.navegar(webview, url_bar)

    def _apply_theme(self, theme_name):
        self.settings.setValue("theme", theme_name)
        self.setProperty("theme", theme_name)
        self.style().unpolish(self)
        self.style().polish(self)

    def _handle_browser_action_click(self, ext_id: str):
        ext_data = self.extensions.get(ext_id, {})
        manifest = ext_data.get("manifest", {})
        action_info = manifest.get("browser_action", {})

        if "default_popup" in action_info:
            self._show_browser_action_popup(ext_id, action_info)
        else:
            self.browser_api.onBrowserActionClicked.emit(ext_id)

    def _show_browser_action_popup(self, ext_id: str, action_info: dict):
        popup_path = os.path.join(self.extensions_path, ext_id, action_info["default_popup"])
        if not os.path.exists(popup_path):
            return

        button = self.findChild(QPushButton, f"browser_action_{ext_id}")
        if not button: return

        popup = QDialog(self, Qt.WindowType.Popup)
        popup.setContentsMargins(0, 0, 0, 0)
        layout = QVBoxLayout(popup)
        layout.setContentsMargins(0, 0, 0, 0)
        
        webview = QWebEngineView()
        page = CustomWebEnginePage(self.persistent_profile, webview)
        page.featurePermissionRequested.connect(self.handle_permission_request)
        page.customDownloadRequested.connect(self._start_custom_download)
        self._setup_page_scripts(page)
        webview.setPage(page)
        webview.setUrl(QUrl.fromLocalFile(popup_path))
        
        webview.loadFinished.connect(lambda ok: webview.page().runJavaScript("document.documentElement.outerHTML", 0, lambda html: popup.setFixedSize(webview.page().contentsSize().toSize())))

        layout.addWidget(webview)
        
        button_pos = button.mapToGlobal(QPoint(0, button.height()))
        popup.move(button_pos)
        popup.show()

    def _find_text(self, text, webview):
        if text:
            webview.findText(text)
        else:
            webview.findText("")
            label = webview.parentWidget().findChild(QWidget, "find_bar").findChild(QLabel, "find_results_label")
            if label:
                label.setText("0/0")

    def _find_next(self, webview):
        find_input = webview.parentWidget().findChild(QWidget, "find_bar").findChild(QLineEdit, "find_input")
        if find_input:
            webview.findText(find_input.text())

    def _find_previous(self, webview):
        find_input = webview.parentWidget().findChild(QWidget, "find_bar").findChild(QLineEdit, "find_input")
        if find_input:
            webview.findText(find_input.text(), QWebEnginePage.FindFlag.FindBackward)

    def _update_find_results(self, result, label):
        if result.numberOfMatches() > 0:
            label.setText(f"{result.activeMatch()}/{result.numberOfMatches()}")
        else:
            label.setText("0/0")

    def _zoom_in(self):
        if webview := self._get_current_webview():
            webview.setZoomFactor(webview.zoomFactor() + 0.1)

    def _zoom_out(self):
        if webview := self._get_current_webview():
            webview.setZoomFactor(webview.zoomFactor() - 0.1)

    def _reset_zoom(self):
        if webview := self._get_current_webview():
            webview.setZoomFactor(1.0)

    def _go_home(self):
        if webview := self._get_current_webview():
            homepage_url = self.settings.value("homepage", "https://www.google.com")
            webview.setUrl(QUrl(homepage_url))

    def _get_dominant_color_from_image(self, image: QImage) -> QColor:
        if image.isNull() or image.width() == 0 or image.height() == 0:
            return QColor()

        if image.width() > 32 or image.height() > 32:
            image = image.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)

        color_counts = {}
        for x in range(0, image.width(), 2):
            for y in range(0, image.height(), 2):
                pixel_color = QColor(image.pixel(x, y))
                
                if (pixel_color.alpha() < 128 or 
                    pixel_color.lightnessF() > 0.9 or 
                    pixel_color.lightnessF() < 0.1 or
                    pixel_color.saturationF() < 0.15):
                    continue
                
                r = round(pixel_color.red() / 20) * 20
                g = round(pixel_color.green() / 20) * 20
                b = round(pixel_color.blue() / 20) * 20
                
                rgb = (r, g, b)
                color_counts[rgb] = color_counts.get(rgb, 0) + 1
        
        if not color_counts:
            return QColor()

        dominant_rgb = max(color_counts, key=color_counts.get)
        dominant_color = QColor(*dominant_rgb)
        
        if dominant_color.lightnessF() < 0.2:
            return dominant_color.lighter(150)
        return dominant_color

    def _on_dominant_color_ready(self, dominant_color: QColor, tab_widget: QWidget, tab_index: int):
        """Aplica el color dominante una vez que ha sido calculado en segundo plano."""
        if tab_index >= self.tabs.count() or self.tabs.widget(tab_index) != tab_widget:
            return

        if dominant_color.isValid():
            tab_widget.setProperty("dominant_color", dominant_color.name())
            if self.tabs.currentIndex() == tab_index:
                self.apply_custom_theme("Custom", dominant_color.name())
        else:
            tab_widget.setProperty("dominant_color", None)
            if self.tabs.currentIndex() == tab_index:
                self.apply_custom_theme("Default")

    def _save_session(self):
        if self.is_incognito: return
        urls = [self.tabs.widget(i).findChild(QWebEngineView).url().toString() for i in range(self.tabs.count()) if self.tabs.widget(i)]
        try:
            with open(self.session_path, "w", encoding="utf-8") as f: json.dump(urls, f)
        except IOError: pass

    def _restore_session(self, open_default_if_empty=True):
        if self.is_incognito or not os.path.exists(self.session_path):
            if open_default_if_empty:
                self.agregar_pestana(self.settings.value("homepage", "https://www.google.com"))
            return
        try:
            with open(self.session_path, "r", encoding="utf-8") as f: urls = json.load(f)
            if urls:
                for url in urls: self.agregar_pestana(url, focus=False)
                if self.tabs.count() > 0: self.tabs.setCurrentIndex(0)
            elif open_default_if_empty:
                self.agregar_pestana(self.settings.value("homepage", "https://www.google.com"))
        except (IOError, json.JSONDecodeError):
            if open_default_if_empty:
                self.agregar_pestana(self.settings.value("homepage", "https://www.google.com"))

    def _toggle_bookmarks_dock(self, checked):
        if self.bookmarks_dock is None:
            self._create_bookmarks_dock()
        self.bookmarks_dock.setVisible(checked)

    def _toggle_downloads_dock(self, checked):
        if self.downloads_dock is None:
            self._create_downloads_dock()
        self.downloads_dock.setVisible(checked)

    def _toggle_history_dock(self, checked):
        if self.history_dock is None:
            self._create_history_dock()
        self.history_dock.setVisible(checked)

    def _toggle_notes_dock(self, checked):
        if self.notes_dock is None:
            self._create_notes_dock()
        self.notes_dock.setVisible(checked)

    def _create_notes_dock(self):
        self.notes_dock = QDockWidget("Notas", self)
        self.notes_dock.setObjectName("NotesDock")

        self.notes_editor = QTextEdit()
        self.notes_editor.setPlaceholderText("Escribe tus notas aquí...")
        
        self.notes_dock.setWidget(self.notes_editor)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.notes_dock)
        self._load_notes()

        if self.bookmarks_dock: self.tabifyDockWidget(self.notes_dock, self.bookmarks_dock)
        if self.downloads_dock: self.tabifyDockWidget(self.notes_dock, self.downloads_dock)
        if self.history_dock: self.tabifyDockWidget(self.notes_dock, self.history_dock)

    def _create_bookmarks_dock(self):
        self.bookmarks_dock = QDockWidget("Favoritos", self)
        self.bookmarks_dock.setObjectName("BookmarksDock")
        
        # Create the main container and layout
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create the list widget that the manager will control
        self.bookmarks_list_widget = QListWidget()
        self.bookmarks_list_widget.itemDoubleClicked.connect(self._go_to_bookmark)
        
        # Instantiate the manager, which will load data and populate the widget
        self.bookmark_manager = BookmarkManager(self.bookmarks_path, self.bookmarks_list_widget)
        
        # Add the (now populated) list widget to the layout
        layout.addWidget(self.bookmarks_list_widget)
        
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Añadir Página Actual")
        add_btn.clicked.connect(self._add_current_page_to_bookmarks)
        delete_btn = QPushButton("Eliminar Seleccionado")
        delete_btn.clicked.connect(self._delete_selected_bookmarks)
        button_layout.addWidget(add_btn)
        button_layout.addWidget(delete_btn)
        if self.is_incognito:
            add_btn.setEnabled(False)
            delete_btn.setEnabled(False)
        layout.addLayout(button_layout)
        
        self.bookmarks_dock.setWidget(container)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.bookmarks_dock)

        if self.downloads_dock: self.tabifyDockWidget(self.bookmarks_dock, self.downloads_dock)
        if self.history_dock: self.tabifyDockWidget(self.bookmarks_dock, self.history_dock)
        if self.notes_dock: self.tabifyDockWidget(self.bookmarks_dock, self.notes_dock)

    def _create_downloads_dock(self):
        self.downloads_dock = QDockWidget("Descargas", self)
        self.downloads_dock.setObjectName("DownloadsDock")

        downloads_container = QWidget()
        downloads_layout = QVBoxLayout(downloads_container)

        self.downloads_table = QTableWidget()
        self.downloads_table.setColumnCount(7)
        self.downloads_table.setHorizontalHeaderLabels(["Archivo", "Tamaño", "Progreso", "Velocidad", "Tiempo Restante", "Estado", "Acciones"])
        self.downloads_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.downloads_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.downloads_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.downloads_table.verticalHeader().setVisible(False)
        self.downloads_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        downloads_layout.addWidget(self.downloads_table)

        clear_downloads_btn = QPushButton("Limpiar Completados")
        clear_downloads_btn.clicked.connect(self._clear_completed_downloads)
        downloads_layout.addWidget(clear_downloads_btn)

        self.downloads_dock.setWidget(downloads_container)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.downloads_dock)

        if self.bookmarks_dock: self.tabifyDockWidget(self.downloads_dock, self.bookmarks_dock)
        if self.history_dock: self.tabifyDockWidget(self.downloads_dock, self.history_dock)
        if self.notes_dock: self.tabifyDockWidget(self.downloads_dock, self.notes_dock)

    def _create_history_dock(self):
        self.history_dock = QDockWidget("Historial", self)
        self.history_dock.setObjectName("HistoryDock")

        history_container = QWidget()
        history_layout = QVBoxLayout(history_container)

        self.history_list_widget = QListWidget()
        self.history_list_widget.itemDoubleClicked.connect(self._go_to_history_item)
        history_layout.addWidget(self.history_list_widget)

        clear_history_btn = QPushButton("Limpiar Historial")
        clear_history_btn.clicked.connect(self._clear_history)
        if self.is_incognito:
            clear_history_btn.setEnabled(False)
        history_layout.addWidget(clear_history_btn)

        self.history_dock.setWidget(history_container)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.history_dock)
        self._update_history_list_widget()

        if self.bookmarks_dock: self.tabifyDockWidget(self.history_dock, self.bookmarks_dock)
        if self.downloads_dock: self.tabifyDockWidget(self.history_dock, self.downloads_dock)
        if self.notes_dock: self.tabifyDockWidget(self.history_dock, self.notes_dock)

    def _show_url_bar_context_menu(self, point: QPoint, url_bar: QLineEdit, webview: QWebEngineView):
        menu = url_bar.createStandardContextMenu()
        menu.addSeparator()
        
        paste_go_action = QAction("Pegar e ir", self)
        clipboard = QApplication.instance().clipboard()
        paste_go_action.setEnabled(clipboard.text().strip() != "")
        paste_go_action.triggered.connect(lambda: self._paste_and_go(webview, url_bar))
        menu.addAction(paste_go_action)
        
        menu.exec(url_bar.mapToGlobal(point))

    def _paste_and_go(self, webview: QWebEngineView, url_bar: QLineEdit):
        clipboard = QApplication.instance().clipboard()
        text = clipboard.text()
        if text:
            url_bar.setText(text)
            self.navegar(webview, url_bar)

    def _update_user_block_list(self, text: str):
        self.settings.setValue("user_block_list", text)
        self.ad_blocker.update_user_block_list(text)

    def _open_profile_folder(self):
        if self.is_incognito:
            QMessageBox.information(self, "Modo Incógnito", "No hay una carpeta de perfil persistente en este modo.")
            return
        
        if self.profile_path and os.path.exists(self.profile_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.profile_path))
        else:
            QMessageBox.warning(self, "Carpeta no encontrada", 
                                "La carpeta del perfil no existe o no se ha configurado.")

    def solicitar_limpiar_perfil(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Confirmar borrado de perfil")
        msg_box.setText("¿Estás seguro de que quieres borrar el perfil?")
        msg_box.setInformativeText(
            "Se borrarán todas las cookies, historiales y datos de sesión.\n"
            "La aplicación se cerrará y deberás volver a abrirla."
        )
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.No)
        
        if msg_box.exec() == QMessageBox.StandardButton.Yes:
            self.about_to_clear_profile = True
            QApplication.instance().quit()

    def mostrar_acerca_de(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def handle_permission_request(self, origin: QUrl, feature: QWebEnginePage.Feature): # MODIFIED
        """Maneja las solicitudes de permisos, permitiendo recordar la decisión del usuario."""
        feature_text_map = {
            QWebEnginePage.Feature.Geolocation: "acceder a tu ubicación",
            QWebEnginePage.Feature.MediaAudioCapture: "usar tu micrófono",
            QWebEnginePage.Feature.MediaVideoCapture: "usar tu cámara",
            QWebEnginePage.Feature.MediaAudioVideoCapture: "usar tu cámara y micrófono",
            QWebEnginePage.Feature.Notifications: "mostrar notificaciones",
            QWebEnginePage.Feature.MouseLock: "bloquear el puntero del ratón",
        }
        feature_key_map = {
            QWebEnginePage.Feature.Geolocation: "geolocation",
            QWebEnginePage.Feature.MediaAudioCapture: "media_audio",
            QWebEnginePage.Feature.MediaVideoCapture: "media_video",
            QWebEnginePage.Feature.MediaAudioVideoCapture: "media_audio_video",
            QWebEnginePage.Feature.Notifications: "notifications",
            QWebEnginePage.Feature.MouseLock: "mouse_lock",
        }

        feature_key = feature_key_map.get(feature)
        if not feature_key: return

        host = origin.host()
        page = self.sender()
        if not isinstance(page, QWebEnginePage): return

        saved_permissions = self.settings.value("site_permissions", {}, type=dict)
        permission_status = saved_permissions.get(host, {}).get(feature_key)

        if permission_status == "granted":
            page.setFeaturePermission(origin, feature, QWebEnginePage.PermissionPolicy.PermissionGrantedByUser)
            return
        elif permission_status == "denied":
            page.setFeaturePermission(origin, feature, QWebEnginePage.PermissionPolicy.PermissionDeniedByUser)
            return

        feature_name = feature_text_map.get(feature, "una función desconocida")
        question = f"El sitio {origin.host()} quiere {feature_name}. ¿Lo permites?"

        dialog = PermissionDialog(question, self)
        result = dialog.exec()

        permission_to_set = QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
        status_to_save = "denied"

        if result == QDialog.DialogCode.Accepted:
            permission_to_set = QWebEnginePage.PermissionPolicy.PermissionGrantedByUser
            status_to_save = "granted"

        page.setFeaturePermission(origin, feature, permission_to_set)

        if dialog.is_remember_checked():
            host_permissions = saved_permissions.get(host, {})
            host_permissions[feature_key] = status_to_save
            saved_permissions[host] = host_permissions
            self.settings.setValue("site_permissions", saved_permissions)

    def _start_custom_download(self, url: QUrl):
        """Inicia una descarga mediante programación desde una acción del menú contextual."""
        self.persistent_profile.download(url)

    def _handle_download_request(self, download: QWebEngineDownloadRequest):
        """Manages a file download request."""
        if self.is_incognito:
            QMessageBox.information(self, "Modo Incógnito", "Las descargas no están soportadas en este modo.")
            download.cancel()
            return
        
        download.accept()
        
        if self.downloads_dock is None:
            self._create_downloads_dock()
        
        self.downloads_dock.setVisible(True)
        self._add_download_to_table(download)

    def _add_download_to_table(self, download: QWebEngineDownloadRequest):
        row = self.downloads_table.rowCount()
        self.downloads_table.insertRow(row)

        filename = os.path.basename(download.suggestedFileName())
        icon_provider = QFileIconProvider()
        file_icon = icon_provider.icon(QFileInfo(filename))

        filename_item = QTableWidgetItem(file_icon, filename)
        size_item = QTableWidgetItem("0 MB")
        speed_item = QTableWidgetItem("...")
        time_remaining_item = QTableWidgetItem("...")
        status_item = QTableWidgetItem("Iniciando...")
        progress_bar = QProgressBar()
        progress_bar.setValue(0)
        progress_bar.setTextVisible(False)

        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        pause_resume_btn = QPushButton("Pausar")
        pause_resume_btn.clicked.connect(lambda: self._toggle_pause_resume_download(download))
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.clicked.connect(lambda: self._cancel_download(download))
        actions_layout.addWidget(pause_resume_btn)
        actions_layout.addWidget(cancel_btn)

        self.downloads_table.setItem(row, 0, filename_item)
        self.downloads_table.setItem(row, 1, size_item)
        self.downloads_table.setCellWidget(row, 2, progress_bar)
        self.downloads_table.setItem(row, 3, speed_item)
        self.downloads_table.setItem(row, 4, time_remaining_item)
        self.downloads_table.setItem(row, 5, status_item)
        self.downloads_table.setCellWidget(row, 6, actions_widget)

        self.downloads[download] = {
            "row": row,
            "progress_bar": progress_bar,
            "actions_widget": actions_widget,
            "status_item": status_item,
            "speed_item": speed_item,
            "time_remaining_item": time_remaining_item,
            "pause_resume_btn": pause_resume_btn,
            "last_update_time": time.time(),
            "last_received_bytes": 0,
            "final_path": None,
        }

        download.totalBytesChanged.connect(lambda: self._update_download_size(download))
        download.receivedBytesChanged.connect(lambda: self._update_download_progress(download))
        download.stateChanged.connect(lambda: self._update_download_state(download))

    def _update_download_size(self, download: QWebEngineDownloadRequest):
        if download in self.downloads:
            row = self.downloads[download]["row"]
            self.downloads_table.item(row, 1).setText(f"{download.totalBytes() / 1024 / 1024:.2f} MB")

    def _update_download_progress(self, download: QWebEngineDownloadRequest):
        if download in self.downloads:
            info = self.downloads[download]
            progress_bar = info["progress_bar"]
            
            current_time = time.time()
            current_bytes = download.receivedBytes()
            
            time_delta = current_time - info["last_update_time"]
            bytes_delta = current_bytes - info["last_received_bytes"]
            
            if time_delta > 0.8 and info["status_item"].text() == "Descargando":
                speed = bytes_delta / time_delta
                if speed < 1024 * 1024:
                    speed_text = f"{speed / 1024:.1f} KB/s"
                else:
                    speed_text = f"{speed / (1024 * 1024):.1f} MB/s"
                info["speed_item"].setText(speed_text)

                info["last_update_time"] = current_time
                info["last_received_bytes"] = current_bytes

                if speed > 0 and download.totalBytes() > 0:
                    bytes_remaining = download.totalBytes() - current_bytes
                    seconds_remaining = bytes_remaining / speed

                    if seconds_remaining < 60:
                        time_text = f"~{int(seconds_remaining)} s"
                    elif seconds_remaining < 3600:
                        minutes = int(seconds_remaining / 60)
                        seconds = int(seconds_remaining % 60)
                        time_text = f"~{minutes}m {seconds}s"
                    else:
                        hours = int(seconds_remaining / 3600)
                        minutes = int((seconds_remaining % 3600) / 60)
                        time_text = f"~{hours}h {minutes}m"
                    info["time_remaining_item"].setText(time_text)
                else:
                    info["time_remaining_item"].setText("...")

            if download.totalBytes() > 0:
                progress = int((current_bytes / download.totalBytes()) * 100)
                progress_bar.setValue(progress)

    def _update_download_state(self, download: QWebEngineDownloadRequest):
        if download in self.downloads:
            info = self.downloads[download]
            state_map = {
                QWebEngineDownloadRequest.DownloadState.DownloadInProgress: "Descargando",
                QWebEngineDownloadRequest.DownloadState.DownloadCompleted: "Completado",
                QWebEngineDownloadRequest.DownloadState.DownloadCancelled: "Cancelado",
                QWebEngineDownloadRequest.DownloadState.DownloadInterrupted: "Fallido",
            }
            info["status_item"].setText(state_map.get(download.state(), "Desconocido"))
            if info["status_item"].text() != "Descargando":
                info["speed_item"].setText("-")
                info["time_remaining_item"].setText("-")

            if download.isFinished():
                self._finalize_download(download)
                try:
                    download.totalBytesChanged.disconnect()
                    download.receivedBytesChanged.disconnect()
                    download.stateChanged.disconnect()
                except TypeError:
                    pass 

    def _finalize_download(self, download: QWebEngineDownloadRequest):
        """Se llama cuando la descarga termina. Mueve el archivo de temporal a final."""
        if download not in self.downloads:
            return

        info = self.downloads[download]
        actions_widget = info["actions_widget"]
        while actions_widget.layout().count():
            if item := actions_widget.layout().takeAt(0):
                if widget := item.widget():
                    widget.deleteLater()

        if download.state() == QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
            temp_path = download.path()
            sanitized_name = sanitize_filename(download.suggestedFileName())
            suggested_path = os.path.join(os.path.expanduser("~"), "Downloads", sanitized_name)

            final_path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo", suggested_path)

            if final_path:
                try:
                    shutil.move(temp_path, final_path)
                    info["final_path"] = final_path
                    self.downloads_table.item(info["row"], 0).setText(os.path.basename(final_path))

                    open_btn = QPushButton("Abrir")
                    open_btn.clicked.connect(lambda: self._open_downloaded_file(download))
                    show_folder_btn = QPushButton("Mostrar")
                    show_folder_btn.clicked.connect(lambda: self._show_download_in_folder(download))
                    actions_widget.layout().addWidget(open_btn)
                    actions_widget.layout().addWidget(show_folder_btn)
                except Exception as e:
                    info["status_item"].setText("Error al mover")
                    QMessageBox.critical(self, "Error de descarga", f"No se pudo mover el archivo descargado:\n{e}")
            else:
                info["status_item"].setText("Cancelado (no guardado)")
                if os.path.exists(temp_path) and os.path.isfile(temp_path):
                    os.remove(temp_path)

    def _toggle_pause_resume_download(self, download: QWebEngineDownloadRequest):
        """Pausa o reanuda una descarga en curso."""
        if download not in self.downloads or download.isFinished():
            return
        
        info = self.downloads[download]
        button = info["pause_resume_btn"]
        
        
        if button.text() == "Pausar":
            download.pause()
            button.setText("Reanudar")
            info["status_item"].setText("Pausado")
            info["speed_item"].setText("0.0 KB/s")
        else:
            download.resume()
            button.setText("Pausar")
            info["status_item"].setText("Descargando")
            
            info["last_update_time"] = time.time()
            info["last_received_bytes"] = download.receivedBytes()

    def _cancel_download(self, download: QWebEngineDownloadRequest):
        if download in self.downloads:
            download.cancel()

    def _open_downloaded_file(self, download: QWebEngineDownloadRequest):
        if download in self.downloads and (path := self.downloads[download].get("final_path")):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _show_download_in_folder(self, download: QWebEngineDownloadRequest):
        if download in self.downloads and (path := self.downloads[download].get("final_path")):
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))

    def _clear_completed_downloads(self):
        rows_to_remove = []
        downloads_to_remove = []
        for download, info in self.downloads.items():
            if download.isFinished():
                rows_to_remove.append(info["row"])
                downloads_to_remove.append(download)
        
        for row in sorted(rows_to_remove, reverse=True):
            self.downloads_table.removeRow(row)

        for download in downloads_to_remove:
            del self.downloads[download]

        for i, download in enumerate(self.downloads.keys()):
            self.downloads[download]['row'] = i

    def _open_downloads_folder(self):
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        QDesktopServices.openUrl(QUrl.fromLocalFile(downloads_path))

    def _apply_page_settings(self, page: QWebEnginePage):
        """Applies all necessary settings to a new or existing page."""
        settings = page.settings()
        
        settings.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.DnsPrefetchEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScreenCaptureEnabled, True)
        if hasattr(QWebEngineSettings.WebAttribute, 'WebRTCPublicInterfacesOnly'):
            settings.setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)

        settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)


        if self.super_memory_saver_enabled:
            settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)
        elif self.battery_saver_enabled:
            settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)

    def _update_blocklist(self):
        """Inicia la actualización de la lista de bloqueo en un hilo separado para no congelar la UI."""
        worker = Worker(self._download_blocklist_task)
        worker.signals.result.connect(self._on_blocklist_download_finished)
        worker.signals.error.connect(self._on_blocklist_download_error)
        
        self.update_adblock_action.setEnabled(False)
        worker.signals.finished.connect(lambda: self.update_adblock_action.setEnabled(True))

        self.threadpool.start(worker)
        self.statusBar().showMessage("Actualizando lista de bloqueo...", 4000)

    def _download_blocklist_task(self):
        """Tarea que se ejecuta en segundo plano para descargar y guardar la lista de bloqueo."""
        url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext"
        with urllib.request.urlopen(url, timeout=20) as response:
            data = response.read().decode('utf-8')
            with open(self.adblock_list_path, "w", encoding="utf-8") as f:
                f.write(data)
        return True

    def _on_blocklist_download_error(self, err_tuple):
        exctype, value, tb_str = err_tuple
        print(f"ERROR: Falló la descarga de la lista de bloqueo:\n{tb_str}")
        self.statusBar().showMessage("Error al actualizar la lista de bloqueo.", 5000)
        QMessageBox.critical(self, "Error de Actualización", f"No se pudo descargar la lista de bloqueo:\n{value}")

    def _toggle_battery_saver(self, enabled):
        if enabled and self.super_memory_saver_enabled:
            for action in self.menuBar().findChildren(QAction):
                if action.text() == "Ahorro de memoria extremo":
                    action.blockSignals(True)
                    action.setChecked(False)
                    action.blockSignals(False)
            self.super_memory_saver_enabled = False

        self.battery_saver_enabled = enabled
        self.settings.setValue("batterySaverEnabled", enabled)
        
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if webview := tab.findChild(QWebEngineView):
                self._apply_page_settings(webview.page())
                webview.reload()
        
        if enabled:
            QMessageBox.information(self, "Ahorro de Batería Activado", "Se ha deshabilitado la carga de imágenes y plugins. Las pestañas se han recargado.")
        else:
            QMessageBox.information(self, "Ahorro de Batería Desactivado", "Se han restaurado las funciones completas. Las pestañas se han recargado.")

    def _toggle_super_memory_saver(self, enabled):
        if enabled:
            reply = QMessageBox.warning(self, "Ahorro de Memoria Extremo",
                                      "<b>¡Atención!</b> Este modo deshabilitará funciones esenciales como <b>JavaScript e imágenes</b>.<br><br>"
                                      "La mayoría de los sitios web modernos no funcionarán correctamente. ¿Deseas continuar?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                for action in self.menuBar().findChildren(QAction):
                    if action.text() == "Ahorro de memoria extremo":
                        action.blockSignals(True)
                        action.setChecked(False)
                        action.blockSignals(False)
                return

        self.super_memory_saver_enabled = enabled
        self.settings.setValue("superMemorySaverEnabled", enabled)
        
        if enabled and self.battery_saver_enabled:
            for action in self.menuBar().findChildren(QAction):
                if action.text() == "Ahorro de batería":
                    action.blockSignals(True)
                    action.setChecked(False)
                    action.blockSignals(False)
            self.battery_saver_enabled = False

        for i in range(self.tabs.count()):
            if webview := self.tabs.widget(i).findChild(QWebEngineView):
                self._apply_page_settings(webview.page())
                webview.reload()
        
        if enabled:
            QMessageBox.information(self, "Modo Extremo Activado", "Se han deshabilitado JavaScript, imágenes y más. Las pestañas se han recargado.")
        else:
            QMessageBox.information(self, "Modo Extremo Desactivado", "Se han restaurado las funciones completas. Las pestañas se han recargado.")

    def _on_blocklist_download_finished(self, success):
        if success:
            self.ad_blocker.load_ad_block_list(self.adblock_list_path)
            self.statusBar().showMessage("Lista de bloqueo actualizada con éxito.", 5000)
            QMessageBox.information(self, "Éxito", "La lista de bloqueo de anuncios ha sido actualizada.")

    def _add_current_page_to_bookmarks(self):
        if not (current_widget := self.tabs.currentWidget()) or not (webview := current_widget.findChild(QWebEngineView)):
            return
        if self.is_incognito or not self.bookmark_manager:
            QMessageBox.information(self, "Modo Incógnito", "Los favoritos no se pueden gestionar en este modo.\n"
                                     "Abre una ventana normal para guardar esta página.")
            return
        url = webview.url().toString()
        title = webview.title() or url

        if not self.bookmark_manager.add(title, url):
            QMessageBox.information(self, "Favorito existente", "Esta página ya está en tus favoritos.")
        else:
            self.actualizar_ui_pestana(webview.url())

    def _delete_selected_bookmarks(self):
        if not self.bookmark_manager or not self.bookmarks_list_widget or not self.bookmarks_list_widget.selectedItems():
            return
        
        selected_items = self.bookmarks_list_widget.selectedItems()
        urls_to_delete = {item.data(Qt.ItemDataRole.UserRole) for item in selected_items}

        if self.bookmark_manager.delete(urls_to_delete):
            # If bookmarks were deleted, update the UI of all tabs
            for i in range(self.tabs.count()):
                if widget := self.tabs.widget(i):
                    if webview := widget.findChild(QWebEngineView):
                        self.actualizar_ui_pestana(webview.url())

    def _go_to_bookmark(self, item: QListWidgetItem):
        url = item.data(Qt.ItemDataRole.UserRole)
        self.agregar_pestana(url)

    def _is_bookmarked(self, url: str) -> bool:
        if not self.bookmark_manager:
            return False
        return self.bookmark_manager.is_bookmarked(url)

    def _load_history(self):
        if not os.path.exists(self.history_path):
            self.history = []
            return
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                self.history = json.load(f)
        except (json.JSONDecodeError, IOError):
            print("Error al cargar el historial. Se iniciará con un historial vacío.")
            self.history = []

    def _save_history(self):
        try:
            with open(self.history_path, "w", encoding="utf-8") as f:
                json.dump(self.history, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"No se pudo guardar el historial: {e}")

    def _add_to_history(self, ok, sender_webview):
        if not ok or self.is_incognito:
            return

        url = sender_webview.url().toString()
        title = sender_webview.title() or url

        if url == "about:blank" or (self.history and self.history[-1]['url'] == url):
            return

        self.history.append({'url': url, 'title': title})
        self._update_history_list_widget()

    def _clear_history(self):
        if self.is_incognito:
            return

        reply = QMessageBox.question(self, 'Limpiar Historial',
                                     "¿Estás seguro de que quieres borrar todo el historial de navegación?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            self.history = []
            self.history_list_widget.clear()
            self._save_history()

    def _go_to_history_item(self, item: QListWidgetItem):
        url = item.data(Qt.ItemDataRole.UserRole)
        if url:
            self.agregar_pestana(url)

    def _update_history_list_widget(self):
        if self.history_list_widget is None:
            return
        self.history_list_widget.clear()
        for entry in reversed(self.history):
            item = QListWidgetItem(f"{entry['title']}\n{entry['url']}")
            item.setData(Qt.ItemDataRole.UserRole, entry['url'])
            self.history_list_widget.addItem(item)

    def _load_extensions(self):
        if self.is_incognito or not os.path.exists(self.extensions_manifest_path):
            self.extensions = {}
            return
        try:
            with open(self.extensions_manifest_path, "r", encoding="utf-8") as f:
                self.extensions = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error al cargar el manifest de extensiones: {e}")
            self.extensions = {}

        for ext_id, ext_data in self.extensions.items():
            if ext_data.get("enabled", False):
                manifest = ext_data.get("manifest", {})
                if "background" in manifest and "scripts" in manifest["background"]:
                    self._load_background_script(ext_id, manifest["background"]["scripts"])

    def _load_background_script(self, ext_id: str, scripts: list):
        if ext_id in self.background_pages: return

        page = QWebEnginePage(self.persistent_profile, self)
        page.featurePermissionRequested.connect(self.handle_permission_request)
        channel = QWebChannel(page)
        page.setWebChannel(channel)
        channel.registerObject("browser_api", self.browser_api)

        self._setup_page_scripts(page)
        
        script_tags = "".join([f'<script src="file:///{os.path.join(self.extensions_path, ext_id, script_file).replace(os.sep, "/")}"></script>' for script_file in scripts])
        html = f"<!DOCTYPE html><html><head><title>BG</title></head><body>{script_tags}</body></html>"
        page.setHtml(html)
        self.background_pages[ext_id] = page

    def _save_extensions(self):
        if self.is_incognito:
            return
        try:
            with open(self.extensions_manifest_path, "w", encoding="utf-8") as f:
                json.dump(self.extensions, f, indent=4)
        except IOError as e:
            QMessageBox.warning(self, "Error", f"No se pudo guardar la configuración de extensiones: {e}")

    def _manage_extensions(self):
        if self.is_incognito:
            QMessageBox.information(self, "Modo Incógnito", "Las extensiones no se pueden gestionar en este modo.")
            return
        
        dialog = ExtensionsDialog(self)
        dialog.exec()
        self._load_extensions() 
    def _setup_page_scripts(self, page: QWebEnginePage):
        """
        Configura e inyecta todos los scripts necesarios (API, extensiones)
        en un mundo JavaScript aislado para mayor seguridad.
        """
        if self.is_incognito:
            return

        if self.password_handler_script_content:
            script_pwd = QWebEngineScript()
            script_pwd.setSourceCode(self.password_handler_script_content)
            page.scripts().insert(script_pwd)

        if not self.qwebchannel_script_content:
            return

        script_qwc = QWebEngineScript()
        script_qwc.setSourceCode(self.qwebchannel_script_content)
        script_qwc.setName("qwebchannel.js")
        script_qwc.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script_qwc.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script_qwc.setRunsOnSubFrames(False)
        page.scripts().insert(script_qwc)

        bootstrap_script_content = """
        new QWebChannel(qt.webChannelTransport, function(channel) {
            window.wemphixAPI = channel.objects.browser_api;
            console.log('Wemphix API conectada de forma segura en mundo aislado.');
            document.dispatchEvent(new Event('wemphixApiReady'));
        });
        """
        script_bootstrap = QWebEngineScript()
        script_bootstrap.setSourceCode(bootstrap_script_content)
        script_bootstrap.setName("wemphixApiBootstrap")
        script_bootstrap.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script_bootstrap.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
        script_bootstrap.setRunsOnSubFrames(False)
        page.scripts().insert(script_bootstrap)

        page_url = page.url().toString()
        for ext_id, ext_data in self.extensions.items():
            if not ext_data.get("enabled", False):
                continue

            manifest = ext_data.get("manifest", {})
            for content_script in manifest.get("content_scripts", []):
                matches_url = any(fnmatch.fnmatch(page_url, pattern) for pattern in content_script.get("matches", []))
                
                if matches_url:
                    for js_file in content_script.get("js", []):
                        script_path = os.path.join(self.extensions_path, ext_id, js_file)
                        if os.path.exists(script_path):
                            try:
                                with open(script_path, "r", encoding="utf-8") as f:
                                    script_ext = QWebEngineScript()
                                    script_ext.setSourceCode(f.read())
                                    script_ext.setName(f"extension_{ext_id}_{js_file}")
                                    # Content scripts must also run in MainWorld to access the API.
                                    script_ext.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                                    script_ext.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
                                    script_ext.setRunsOnSubFrames(False)
                                    page.scripts().insert(script_ext)
                            except Exception as e:
                                print(f"Error al inyectar el script '{js_file}' de la extensión '{manifest.get('name', ext_id)}': {e}")
    
    def _run_streaming_diagnostics(self):
        dialog = StreamingDiagnosticsDialog(self)
        dialog.exec()

    def _show_password_generator(self):
        if not (webview := self._get_current_webview()): return
        
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec():
            password = dialog.get_password()
            escaped_password = password.replace('\\', '\\\\').replace("'", "\\'")
            webview.page().runJavaScript(f"window.wemphixFillPassword('{escaped_password}');")

    def actualizar_ui_pestana(self, qurl):
        sender_webview = self.sender()
        if not isinstance(sender_webview, QWebEngineView):
            return

        current_tab = sender_webview.parentWidget().parentWidget()
        if current_tab:
            if url_bar := current_tab.findChild(QLineEdit):
                url_bar.setText(qurl.toString())
            
            if add_bookmark_btn := current_tab.findChild(QPushButton, "add_bookmark_btn"):
                if self._is_bookmarked(qurl.toString()):
                    add_bookmark_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
                else:
                    add_bookmark_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))

    def actualizar_titulo_pestana(self, title: str):
        sender_webview = self.sender()
        if sender_webview:
            for i in range(self.tabs.count()):
                widget = self.tabs.widget(i)
                if widget and widget.findChild(QWebEngineView) == sender_webview:
                    if not self.is_incognito:
                        tab_info = {"index": i, "title": title, "url": sender_webview.url().toString()}
                        self.browser_api.tabUpdated.emit(tab_info)
                    
                    group_info = widget.property("tab_group")
                    if group_info:
                        widget.setProperty("original_title", title)
                        color_map = {"blue": "🔵", "red": "🔴", "green": "🟢", "yellow": "🟡", "purple": "🟣", "gray": "⚪"}
                        emoji = color_map.get(group_info["color"], "⚫")
                        self.tabs.setTabText(i, f'{emoji} {group_info["name"]} | {title}')
                    else:
                        self.tabs.setTabText(i, title)
                    break

    def actualizar_icono_pestana(self, icon: QIcon):
        sender_webview = self.sender()
        if sender_webview:
            for i in range(self.tabs.count()):
                if self.tabs.widget(i) and self.tabs.widget(i).findChild(QWebEngineView) == sender_webview:
                    widget = self.tabs.widget(i)
                    self._update_tab_icon(i)

                    if self.settings.value("custom_theme") == "Adaptativo":
                        if not icon.isNull():
                            pixmap = icon.pixmap(16, 16)
                            image = pixmap.toImage().convertToFormat(QImage.Format.Format_RGBA8888)
                            dominant_color = self._get_dominant_color_from_image(image)
                            
                            if dominant_color.isValid():
                                widget.setProperty("dominant_color", dominant_color.name())
                                if self.tabs.currentIndex() == i:
                                    self.apply_custom_theme("Custom", dominant_color.name())
                            else:
                                widget.setProperty("dominant_color", None)
                                if self.tabs.currentIndex() == i:
                                    self.apply_custom_theme("Default")
                    break

    def _update_tab_icon(self, index: int):
        if widget := self.tabs.widget(index):
            if webview := widget.findChild(QWebEngineView):
                page = webview.page()
                icon = QIcon()

                is_muted = hasattr(page, 'isAudioMuted') and page.isAudioMuted()
                is_audible = hasattr(page, 'isAudible') and page.isAudible()

                if is_muted:
                    icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolumeMuted)
                elif is_audible:
                    icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume)
                else:
                    icon = page.icon() or QIcon()
                self.tabs.setTabIcon(index, icon)

    def actualizar_estado_botones_nav(self):
        """
        Actualiza el estado (activado/desactivado) de los botones de navegación
        de la pestaña que acaba de terminar de cargar una página.
        """
        sender_webview = self.sender()
        if not isinstance(sender_webview, QWebEngineView):
            return


        current_tab = sender_webview.parentWidget().parentWidget()
        if current_tab:
            atras_btn = current_tab.findChild(QPushButton, "atras_btn")
            adelante_btn = current_tab.findChild(QPushButton, "adelante_btn")

            if atras_btn and adelante_btn:
                history = sender_webview.history()
                atras_btn.setEnabled(history.canGoBack())
                adelante_btn.setEnabled(history.canGoForward())

    def cerrar_pestana(self, index):
        if self.tabs.count() > 1:
            widget_a_cerrar = self.tabs.widget(index)
            self.tabs.removeTab(index)
            if not self.is_incognito:
                self.browser_api.tabRemoved.emit(index)

            if widget_a_cerrar:
                widget_a_cerrar.deleteLater()
        else:
            self.close()

    def _close_tab_by_id(self, tab_id: str):
        for i in range(self.tabs.count()):
            if widget := self.tabs.widget(i):
                if widget.property("tab_id") == tab_id:
                    self.cerrar_pestana(i)
                    return

    def _update_tab_url(self, tab_id: str, new_url: str):
        for i in range(self.tabs.count()):
            if widget := self.tabs.widget(i):
                if widget.property("tab_id") == tab_id:
                    if webview := widget.findChild(QWebEngineView):
                        webview.setUrl(QUrl(new_url))
                    return

    def _query_tabs(self, query_info: dict) -> list:
        results = []
        all_tabs = self.browser_api.getAllTabs()
        
        for tab in all_tabs:
            if query_info.get('active', False) and self.tabs.currentIndex() == tab['index']:
                results.append(tab)
        return results

    def _handle_audio_state_change(self):
        page = self.sender()
        if page:
            for i in range(self.tabs.count()):
                widget = self.tabs.widget(i)
                if widget and widget.findChild(QWebEngineView).page() == page:
                    self._update_tab_icon(i)
                    break

    def _toggle_mute_tab(self, index: int):
        if widget := self.tabs.widget(index):
            if page := widget.findChild(QWebEngineView).page():
                if hasattr(page, 'setAudioMuted'):
                    page.setAudioMuted(not page.isAudioMuted())

    def _show_tab_context_menu(self, point: QPoint):
        index = self.tabs.tabBar().tabAt(point)
        if index == -1:
            return

        menu = QMenu(self)
        menu.addAction("Recargar", lambda: self._reload_tab(index))
        menu.addAction("Duplicar", lambda: self._duplicate_tab(index))
        menu.addSeparator()
        menu.addAction("Cerrar Pestaña", lambda: self.cerrar_pestana(index))
        menu.addAction("Cerrar Otras Pestañas", lambda: self._close_other_tabs(index))
        menu.addAction("Cerrar Pestañas a la Derecha", lambda: self._close_tabs_to_right(index))
        if widget := self.tabs.widget(index):
            page = widget.findChild(QWebEngineView).page()

            menu.addSeparator()
            group_menu = menu.addMenu("Grupos de Pestañas")
            new_group_action = group_menu.addAction("Añadir a nuevo grupo...")
            new_group_action.triggered.connect(lambda: self._create_new_tab_group(index))
            if widget.property("tab_group"):
                remove_group_action = group_menu.addAction("Quitar del grupo")
                remove_group_action.triggered.connect(lambda: self._remove_from_group(index))
            
            if page:
                if hasattr(page, 'isAudible') and (page.isAudible() or page.isAudioMuted()):
                    menu.addSeparator()
                    mute_action = menu.addAction("Silenciar Pestaña")
                    mute_action.setCheckable(True)
                    mute_action.setChecked(page.isAudioMuted())
                    mute_action.triggered.connect(lambda checked, i=index: self._toggle_mute_tab(i))

        menu.exec(self.tabs.mapToGlobal(point))

    def _reload_tab(self, index: int):
        if widget := self.tabs.widget(index):
            if webview := widget.findChild(QWebEngineView):
                webview.reload()

    def _duplicate_tab(self, index: int):
        if widget := self.tabs.widget(index):
            if webview := widget.findChild(QWebEngineView):
                self.agregar_pestana(webview.url().toString())

    def _close_other_tabs(self, index: int):
        for i in range(self.tabs.count() - 1, -1, -1):
            if i != index:
                self.cerrar_pestana(i)

    def _close_tabs_to_right(self, index: int):
        for i in range(self.tabs.count() - 1, index, -1):
            self.cerrar_pestana(i)

    def _load_notes(self):
        if self.is_incognito or not self.notes_path: return
        try:
            if os.path.exists(self.notes_path):
                with open(self.notes_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if self.notes_editor:
                        self.notes_editor.setPlainText(content)
        except IOError as e:
            print(f"No se pudieron cargar las notas: {e}")

    def _save_notes(self):
        if self.is_incognito or not self.notes_editor: return
        try:
            content = self.notes_editor.toPlainText()
            with open(self.notes_path, "w", encoding="utf-8") as f:
                f.write(content)
        except IOError as e:
            print(f"No se pudieron guardar las notas: {e}")

    def _create_new_tab_group(self, index: int):
        dialog = TabGroupDialog(self)
        if dialog.exec():
            name, color = dialog.get_group_info()
            if widget := self.tabs.widget(index):
                webview = widget.findChild(QWebEngineView)
                original_title = webview.title() if webview else "Pestaña"

                widget.setProperty("original_title", original_title)
                widget.setProperty("tab_group", {"name": name, "color": color})
                self.actualizar_titulo_pestana(original_title)

    def _remove_from_group(self, index: int):
        widget = self.tabs.widget(index)
        if widget:
            original_title = widget.property("original_title")
            widget.setProperty("tab_group", None)
            widget.setProperty("original_title", None)
            self.tabs.setTabText(index, original_title or "Pestaña")

    def event(self, event: QEvent) -> bool:
        """Maneja eventos de la aplicación, como la reanudación desde la suspensión."""
        if event.type() == QEvent.Type.ApplicationStateChange:
            new_state = QApplication.instance().applicationState()
            if self.last_app_state == Qt.ApplicationState.ApplicationSuspended and new_state == Qt.ApplicationState.ApplicationActive:
                print("INFO: Aplicación reanudada desde suspensión. Refrescando la pestaña actual para evitar bloqueos.")
                QTimer.singleShot(1500, self._handle_resume_from_suspend)
            self.last_app_state = new_state
        return super().event(event)

    def _handle_resume_from_suspend(self):
        """Recarga la pestaña actual para restaurar el estado de WebEngine después de una suspensión."""
        print("INFO: Ejecutando recarga post-suspensión.")
        if webview := self._get_current_webview():
            webview.reload()

    def _start_rgb_theme(self):
        if not self.rgb_theme_timer.isActive():
            self.rgb_hue = 0
            self.rgb_theme_timer.start(50)

    def _stop_rgb_theme(self):
        if self.rgb_theme_timer.isActive():
            self.rgb_theme_timer.stop()

    def _update_rgb_theme(self):
        self.rgb_hue = (self.rgb_hue + 1) % 360
        color = QColor.fromHsv(self.rgb_hue, 200, 220)
        self._apply_theme_stylesheet("Custom", color.name())

    def apply_custom_theme(self, theme_name, custom_color_hex=None):
        self._stop_rgb_theme() # Stop RGB timer by default when changing themes

        self.settings.setValue("custom_theme", theme_name)
        if theme_name == "Custom":
            self.settings.setValue("custom_theme_color", custom_color_hex)

        if theme_name == "RGB Dinámico":
            self._start_rgb_theme()
            return # The timer will handle applying the stylesheet

        if theme_name == "Adaptativo":
            self.apply_custom_theme("Default")
            return

        self._apply_theme_stylesheet(theme_name, custom_color_hex)

    def _apply_theme_stylesheet(self, theme_name, custom_color_hex=None):
        if theme_name is None or theme_name == "Default":
            current_app_theme = self.settings.value("theme", "Sistema")
            is_dark = False
            if current_app_theme == "Oscuro":
                is_dark = True
            elif current_app_theme == "Sistema":
                is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128

            default_security_bg = "rgba(255, 255, 255, 0.1)" if is_dark else "rgba(0, 0, 0, 0.08)"
            default_security_hover_bg = "rgba(255, 255, 255, 0.15)" if is_dark else "rgba(0, 0, 0, 0.12)"

            self.setStyleSheet(f"""
                #SecurityIndicatorWidget {{
                    background-color: {default_security_bg};
                    border-radius: 10px;
                }}
                #SecurityIndicatorWidget:hover {{
                    background-color: {default_security_hover_bg};
                }}
            """)
            return

        themes = {
            'Azul Océano': '#007acc',
            'Verde Bosque': '#228B22',
            'Naranja Atardecer': '#ff4500',
            'Púrpura Real': '#8a2be2',
            'Gris Grafito': '#555555',
        }

        base_hex = None
        if theme_name == "Custom":
            base_hex = custom_color_hex
        else:
            base_hex = themes.get(theme_name)

        if not base_hex:
            return

        base_color = QColor(base_hex)
        text_color = "white" if base_color.lightness() < 140 else "black"
        highlight_color = base_color.lighter(115).name()
        darker_color = base_color.darker(115).name()

        security_bg = "rgba(255, 255, 255, 0.15)" if text_color == "white" else "rgba(0, 0, 0, 0.08)"
        security_hover_bg = "rgba(255, 255, 255, 0.25)" if text_color == "white" else "rgba(0, 0, 0, 0.12)"

        current_app_theme = self.settings.value("theme", "Sistema")
        if current_app_theme == "Oscuro":
            inactive_tab_bg = "#3a3a3a"
            inactive_tab_text = "white"
            inactive_tab_border = "#2a2a2a"
            inactive_tab_hover_bg = "#4a4a4a"
        else:
            inactive_tab_bg = "#e1e1e1"
            inactive_tab_text = "black"
            inactive_tab_border = "#c0c0c0"
            inactive_tab_hover_bg = "#f0f0f0"

        stylesheet = f"""
            #NavBarWidget {{
                background-color: {base_hex};
            }}
            #SecurityIndicatorWidget {{
                background-color: {security_bg};
                border-radius: 10px;
            }}
            #SecurityIndicatorWidget:hover {{
                background-color: {security_hover_bg};
            }}
            #SecurityIndicatorWidget QLabel {{
                /* Asegura que las etiquetas de texto e icono dentro no tengan su propio fondo */
                background-color: transparent;
                border: none;
            }}
            #NavBarWidget QPushButton {{
                background: transparent;
                border: none;
                color: {text_color};
            }}
            #NavBarWidget QPushButton:hover {{
                background-color: {highlight_color};
            }}
            #NavBarWidget QLineEdit {{
                border: 1px solid {darker_color};
                background-color: white; color: black; border-radius: 3px; padding: 2px 4px;
            }}
            QTabBar::tab:selected {{
                background: {base_hex}; color: {text_color}; border: 1px solid {darker_color};
                border-bottom: 1px solid {base_hex}; border-top-left-radius: 4px; border-top-right-radius: 4px; padding: 4px 8px;
            }}
            QTabBar::tab:!selected {{
                background: {inactive_tab_bg}; color: {inactive_tab_text}; border: 1px solid {inactive_tab_border};
                border-bottom: 1px solid {darker_color}; border-top-left-radius: 4px; border-top-right-radius: 4px; padding: 4px 8px;
            }}
            QTabBar::tab:!selected:hover {{ background: {inactive_tab_hover_bg}; }}
            QTabWidget::pane {{ border: 1px solid {darker_color}; border-top: none; }}
        """
        self.setStyleSheet(stylesheet)

    def _check_for_readable_content(self, webview: QWebEngineView):
        """Comprueba si la página actual parece un artículo y muestra el botón de modo lectura si es así."""
        if not webview: return
        # Si ya estamos en modo lectura, no hagas nada.
        tab_widget = webview.parentWidget().parentWidget()
        if tab_widget and tab_widget.property("in_reader_mode"):
            return

        webview.page().toHtml(lambda html, wv=webview: self._process_html_for_readability(html, wv))

    def _process_html_for_readability(self, html: str, webview: QWebEngineView):
        """Lanza un worker para analizar el HTML en segundo plano y determinar si es legible."""
        # Si la pestaña o el webview ya no existen, no hacer nada.
        if not webview or not webview.parentWidget():
            return

        worker = Worker(self._is_html_readable_task, html)
        # Conectamos la señal de resultado a un método que actualizará la UI, pasando el webview como referencia.
        worker.signals.result.connect(lambda is_readable, wv=webview: self._on_readability_checked(is_readable, wv))
        worker.signals.error.connect(lambda err: print(f"ERROR: Worker de Readability falló: {err[1]}"))
        self.threadpool.start(worker)

    def _is_html_readable_task(self, html: str) -> bool:
        """
        Tarea que se ejecuta en un hilo separado para analizar el HTML con la librería readability.
        Esto evita congelar la interfaz de usuario.
        """
        if not html:
            return False
        try:
            doc = readability.Document(html)
            return len(doc.summary()) > 500
        except Exception as e:
            print(f"ERROR: Excepción en la librería readability: {e}")
            return False

    def _on_readability_checked(self, is_readable: bool, webview: QWebEngineView):
        """
        Callback que se ejecuta en el hilo principal cuando el worker de legibilidad termina.
        Actualiza de forma segura el botón de modo lectura.
        """
        if not webview or not webview.parentWidget() or not webview.parentWidget().parentWidget():
            return

        tab_widget = webview.parentWidget().parentWidget()
        if self.tabs.indexOf(tab_widget) == -1:
            return 

        tab_widget.setProperty("is_readable", is_readable)
        if reader_btn := tab_widget.findChild(QPushButton, "reader_mode_btn"):
            
            in_reader_mode = tab_widget.property("in_reader_mode") or False
            reader_btn.setVisible(is_readable and not in_reader_mode)
        
        if tab_widget := webview.parentWidget().parentWidget():
            if self.tabs.currentWidget() == tab_widget:
                in_reader_mode = tab_widget.property("in_reader_mode") or False
                self.reader_mode_action.setEnabled(is_readable or in_reader_mode)

    def _toggle_reader_mode(self, checked=None):
        """Activa o desactiva el modo de lectura para la pestaña actual."""
        if not (webview := self._get_current_webview()):
            return
        
        tab_widget = webview.parentWidget().parentWidget()
        if not tab_widget:
            return

        in_reader_mode = tab_widget.property("in_reader_mode") or False

        if in_reader_mode:
            
            if original_url := tab_widget.property("original_url"):
                webview.setUrl(QUrl(original_url))
            tab_widget.setProperty("in_reader_mode", False)
            
            if reader_btn := tab_widget.findChild(QPushButton, "reader_mode_btn"):
                reader_btn.setText("📖")
                reader_btn.setToolTip("Entrar en Modo Lectura")
                is_readable = tab_widget.property("is_readable") or False
                reader_btn.setVisible(is_readable)
            
            self.reader_mode_action.setChecked(False)
        else:
            # Entrar en modo lectura
            original_url = webview.url()
            tab_widget.setProperty("original_url", original_url.toString())
            webview.page().toHtml(lambda html, wv=webview, url=original_url: self._activate_reader_mode(html, wv, url))

    def _activate_reader_mode(self, html: str, webview: QWebEngineView, base_url: QUrl):
        """Genera y muestra la vista de lectura."""
        doc = readability.Document(html)
        title = doc.title()
        content = doc.summary()

        palette = QApplication.instance().palette()
        is_dark_theme = palette.color(QPalette.ColorRole.Window).lightness() < 128
        bg_color = "#1e1e1e" if is_dark_theme else "#fdfdfd"
        text_color = "#dcdcdc" if is_dark_theme else "#222222"
        link_color = "#569cd6" if is_dark_theme else "#0066cc"

        reader_html = f"""
        <!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Georgia", serif; background-color: {bg_color}; color: {text_color}; line-height: 1.7; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
            h1, h2, h3 {{ line-height: 1.3; }}
            a {{ color: {link_color}; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            img, video, figure {{ max-width: 100%; height: auto; border-radius: 8px; }}
            pre, code {{ background-color: rgba(128, 128, 128, 0.15); padding: 2px 5px; border-radius: 4px; font-family: "Courier New", monospace; }}
            pre {{ padding: 1em; overflow-x: auto; }}
        </style></head><body><h1>{title}</h1>{content}</body></html>
        """
        
        if tab_widget := webview.parentWidget().parentWidget():
            webview.page().setHtml(reader_html, base_url)
            tab_widget.setProperty("in_reader_mode", True)
            
            if reader_btn := tab_widget.findChild(QPushButton, "reader_mode_btn"):
                reader_btn.setText("❌")
                reader_btn.setToolTip("Salir del Modo Lectura")
                reader_btn.setVisible(True)
            
            self.reader_mode_action.setChecked(True)

    def _capture_visible_area(self):
        """Toma una captura de pantalla del área visible del navegador."""
        if not (webview := self._get_current_webview()): return
        pixmap = webview.grab()
        self._save_screenshot(pixmap)

    def _capture_full_page(self):
        """Inicia el proceso de captura de la página completa."""
        if not (webview := self._get_current_webview()): return

        self.setEnabled(False)
        self._screenshot_parts = []
        self._screenshot_webview = webview
        self._screenshot_initial_scroll = webview.page().scrollPosition()

        webview.page().runJavaScript("window.scrollTo(0, 0);", 0, self._on_scrolled_to_top_for_screenshot)

    def _on_scrolled_to_top_for_screenshot(self, _=None):
        QTimer.singleShot(200, self._get_page_dimensions_for_screenshot)

    def _get_page_dimensions_for_screenshot(self):
        js_code = "[document.documentElement.scrollHeight, window.innerHeight];"
        self._screenshot_webview.page().runJavaScript(js_code, 0, self._start_scrolling_capture)

    def _start_scrolling_capture(self, dimensions):
        self._screenshot_total_height, self._screenshot_view_height = dimensions
        if self._screenshot_view_height <= 0:
            QMessageBox.critical(self, "Error de Captura", "No se pudo determinar el tamaño de la página.")
            self._cleanup_screenshot_session()
            return
        
        self._capture_next_chunk()

    def _capture_next_chunk(self):
        pixmap = self._screenshot_webview.grab()
        
        current_scroll_y = self._screenshot_webview.page().scrollPosition().y()
        if current_scroll_y + self._screenshot_view_height >= self._screenshot_total_height:
            last_chunk_height = self._screenshot_total_height - int(current_scroll_y)
            if last_chunk_height > 0:
                pixmap = pixmap.copy(0, 0, pixmap.width(), last_chunk_height)

        self._screenshot_parts.append(pixmap)

        if current_scroll_y + self._screenshot_view_height >= self._screenshot_total_height:
            self._stitch_and_save_images()
        else:
            next_y = current_scroll_y + self._screenshot_view_height
            self._screenshot_webview.page().runJavaScript(f"window.scrollTo(0, {next_y});", 0, self._on_chunk_scrolled)

    def _on_chunk_scrolled(self, _=None):
        QTimer.singleShot(100, self._capture_next_chunk)

    def _stitch_and_save_images(self):
        if not self._screenshot_parts:
            self._cleanup_screenshot_session()
            QMessageBox.warning(self, "Error de Captura", "No se capturaron imágenes.")
            return

        final_width = self._screenshot_parts[0].width()
        final_height = sum(p.height() for p in self._screenshot_parts)
        
        final_image = QPixmap(final_width, final_height)
        final_image.fill(Qt.GlobalColor.white)
        
        painter = QPainter(final_image)
        current_y = 0
        for part in self._screenshot_parts:
            painter.drawPixmap(0, current_y, part)
            current_y += part.height()
        painter.end()
        
        self._cleanup_screenshot_session()
        self._save_screenshot(final_image)

    def _cleanup_screenshot_session(self):
        if self._screenshot_webview:
            scroll_pos = self._screenshot_initial_scroll
            self._screenshot_webview.page().runJavaScript(f"window.scrollTo({int(scroll_pos.x())}, {int(scroll_pos.y())});")

        self._screenshot_parts = []
        self._screenshot_webview = None
        self.setEnabled(True)

    def _save_screenshot(self, pixmap: QPixmap):
        """Abre un diálogo para guardar la captura de pantalla."""
        if pixmap.isNull():
            QMessageBox.warning(self, "Error de Captura", "No se pudo tomar la captura de pantalla.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar Captura", os.path.join(os.path.expanduser("~"), "Downloads", "captura.png"), "Imágenes (*.png *.jpg)")
        if path and not pixmap.save(path):
            QMessageBox.critical(self, "Error al Guardar", f"No se pudo guardar la imagen en:\n{path}")

class ExtensionsDialog(QDialog):
    def __init__(self, parent: Navegador):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Gestionar Extensiones")
        self.setMinimumSize(400, 300)

        self.layout = QVBoxLayout(self)

        self.list_widget = QListWidget()
        self.list_widget.itemChanged.connect(self._toggle_extension)
        self.layout.addWidget(self.list_widget)

        button_layout = QHBoxLayout()
        add_btn = QPushButton("Añadir Extensión...")
        add_btn.clicked.connect(self._add_extension)
        remove_btn = QPushButton("Eliminar Seleccionada")
        remove_btn.clicked.connect(self._remove_extension)
        button_layout.addWidget(add_btn)
        button_layout.addWidget(remove_btn)
        self.layout.addLayout(button_layout)

        self._populate_list()

    def _populate_list(self):
        self.list_widget.blockSignals(True)
        self.list_widget.clear()
        for ext_id, data in self.main_window.extensions.items():
            manifest = data.get("manifest", {})
            name = manifest.get("name", "Extensión sin nombre")
            version = manifest.get("version", "")
            
            item = QListWidgetItem(f"{name} (v{version})")
            item.setData(Qt.ItemDataRole.UserRole, ext_id)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if data.get("enabled") else Qt.CheckState.Unchecked)
            self.list_widget.addItem(item)
        self.list_widget.blockSignals(False)

    def _toggle_extension(self, item: QListWidgetItem):
        ext_id = item.data(Qt.ItemDataRole.UserRole)
        if ext_id in self.main_window.extensions:
            self.main_window.extensions[ext_id]["enabled"] = (item.checkState() == Qt.CheckState.Checked)
            self.main_window._save_extensions()

    def _add_extension(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Añadir Extensión",
            "",
            "Archivos de Extensión (manifest.json *.zip);;Todos los archivos (*.*)"
        )

        if not file_path:
            return

        source_dir = None
        temp_dir_to_clean = None

        try:
            if file_path.lower().endswith('.zip'):
                temp_dir_to_clean = tempfile.mkdtemp(prefix="wemphix-ext-")
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir_to_clean)
                    source_dir = temp_dir_to_clean
                except (zipfile.BadZipFile, IOError) as e:
                    QMessageBox.critical(self, "Error de ZIP", f"No se pudo descomprimir el archivo de la extensión:\n{e}")
                    return

            elif os.path.basename(file_path) == 'manifest.json':
                source_dir = os.path.dirname(file_path)
            else:
                QMessageBox.warning(self, "Archivo no válido", "Por favor, selecciona un archivo 'manifest.json' o un archivo '.zip' que contenga una extensión.")
                return

            if source_dir is None: return

            manifest_path = os.path.join(source_dir, "manifest.json")
            if not os.path.exists(manifest_path):
                QMessageBox.warning(self, "Error", "La carpeta o archivo ZIP no contiene un 'manifest.json' en su raíz.")
                return

            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            ext_id = str(uuid.uuid4())
            target_dir = os.path.join(self.main_window.extensions_path, ext_id)

            shutil.copytree(source_dir, target_dir)
            self.main_window.extensions[ext_id] = {"manifest": manifest, "enabled": True}
            self.main_window._save_extensions()
            self._populate_list()
            QMessageBox.information(self, "Éxito", f"Extensión '{manifest.get('name', 'desconocida')}' instalada.\n\nReinicia el navegador para que los cambios surtan efecto por completo.")

        except Exception as e:
            QMessageBox.critical(self, "Error de Instalación", f"Ocurrió un error inesperado durante la instalación:\n{e}")
        finally:
            if temp_dir_to_clean and os.path.exists(temp_dir_to_clean):
                shutil.rmtree(temp_dir_to_clean)

    def _remove_extension(self):
        current_item = self.list_widget.currentItem()
        if not current_item:
            return

        ext_id = current_item.data(Qt.ItemDataRole.UserRole)
        ext_name = self.main_window.extensions.get(ext_id, {}).get("manifest", {}).get("name", ext_id)

        reply = QMessageBox.question(self, "Confirmar", f"¿Seguro que quieres eliminar la extensión '{ext_name}'?")
        if reply == QMessageBox.StandardButton.Yes:
            if ext_id in self.main_window.extensions:
                ext_folder = os.path.join(self.main_window.extensions_path, ext_id)
                if os.path.exists(ext_folder):
                    try:
                        shutil.rmtree(ext_folder)
                    except OSError as e:
                        QMessageBox.warning(self, "Error", f"No se pudo borrar la carpeta de la extensión:\n{e}")
                
                del self.main_window.extensions[ext_id]
                self.main_window._save_extensions()
                self._populate_list()

class TabSearchDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Buscar Pestañas")
        self.setMinimumSize(500, 400)
        self.setGeometry(QStyle.alignedRect(Qt.LayoutDirection.LeftToRight, Qt.AlignmentFlag.AlignCenter, self.size(), self.main_window.geometry()))

        self.layout = QVBoxLayout(self)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Escribe para buscar por título o URL...")
        self.search_input.textChanged.connect(self._filter_tabs)
        
        self.tabs_list = QListWidget()
        self.tabs_list.itemActivated.connect(self._go_to_tab)
        
        self.layout.addWidget(self.search_input)
        self.layout.addWidget(self.tabs_list)
        
        self._populate_list()
        
        self.search_input.setFocus()
        if self.tabs_list.count() > 0:
            self.tabs_list.setCurrentRow(0)

    def _create_tab_item_widget(self, icon: QIcon, title: str, url: str):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        icon_label = QLabel()
        if not icon.isNull():
            icon_label.setPixmap(icon.pixmap(16, 16))
        else:
            icon_label.setPixmap(self.main_window.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon).pixmap(16, 16))
        
        text_layout = QVBoxLayout()
        text_layout.setSpacing(0)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold;")
        
        url_label = QLabel(url)
        url_label.setStyleSheet("color: grey;")
        
        text_layout.addWidget(title_label)
        text_layout.addWidget(url_label)
        
        layout.addWidget(icon_label)
        layout.addLayout(text_layout)
        
        return widget

    def _populate_list(self):
        self.tabs_list.clear()
        for i in range(self.main_window.tabs.count()):
            widget = self.main_window.tabs.widget(i)
            if not widget: continue
            
            webview = widget.findChild(QWebEngineView)
            if not webview: continue

            title = self.main_window.tabs.tabText(i)
            url = webview.url().toString()
            icon = webview.page().icon()

            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, i)
            item.setData(Qt.ItemDataRole.StatusTipRole, f"{title}\n{url}")

            item_widget = self._create_tab_item_widget(icon, title, url)
            item.setSizeHint(item_widget.sizeHint())
            
            self.tabs_list.addItem(item)
            self.tabs_list.setItemWidget(item, item_widget)

    def _filter_tabs(self):
        query = self.search_input.text().lower()
        for i in range(self.tabs_list.count()):
            item = self.tabs_list.item(i)
            search_text = item.data(Qt.ItemDataRole.StatusTipRole).lower()
            item.setHidden(query not in search_text)

    def _go_to_tab(self, item):
        index = item.data(Qt.ItemDataRole.UserRole)
        self.main_window.tabs.setCurrentIndex(index)
        self.accept()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)

class TabGroupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Crear Grupo de Pestañas")
        self.layout = QVBoxLayout(self)
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Nombre del grupo")
        self.layout.addWidget(self.name_input)
        
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        color_buttons_layout = QHBoxLayout()
        self.colors = {"gray": "⚪", "red": "🔴", "yellow": "🟡", "green": "🟢", "blue": "🔵", "purple": "🟣"}
        self.selected_color = "gray"
        
        for color, emoji in self.colors.items():
            btn = QPushButton(emoji)
            btn.setCheckable(True)
            color_buttons_layout.addWidget(btn)
            self.button_group.addButton(btn)
            if color == self.selected_color:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked, c=color: self.select_color(c))
        
        self.layout.addLayout(color_buttons_layout)
        
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.layout.addWidget(button_box)

    def select_color(self, color):
        self.selected_color = color

    def get_group_info(self):
        return self.name_input.text() or "Grupo", self.selected_color

class PersonalizationDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Personalizar Apariencia")
        self.setMinimumWidth(300)

        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(10)
        self.layout.addWidget(QLabel("<b>Elige un tema de color:</b>"))

        self.themes = {
            'Default': None, 
            'Adaptativo': 'adaptive',
            'RGB Dinámico': 'rgb',
            'Azul Océano': '#007acc', 
            'Verde Bosque': '#228B22', 
            'Naranja Atardecer': '#ff4500', 
            'Púrpura Real': '#8a2be2',
            'Gris Grafito': '#555555'
        }

        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)

        row, col = 0, 0
        for name, color_hex in self.themes.items():
            button = QPushButton(name)
            button.setMinimumHeight(40)
            if color_hex and color_hex not in ['adaptive', 'rgb']:
                qcolor = QColor(color_hex)
                text_color = "white" if qcolor.lightness() < 128 else "black"
                button.setStyleSheet(f"background-color: {color_hex}; color: {text_color}; border-radius: 5px; font-weight: bold;")
            
            button.clicked.connect(lambda checked, n=name: self.apply_and_close(n))
            grid_layout.addWidget(button, row, col)
            
            col += 1
            if col > 1:
                col = 0
                row += 1
        
        custom_color_btn = QPushButton("Color Personalizado...")
        custom_color_btn.setMinimumHeight(40)
        custom_color_btn.clicked.connect(self.pick_custom_color)
        
        if col > 0:
            row += 1
            col = 0
        grid_layout.addWidget(custom_color_btn, row, 0, 1, 2)
        
        self.layout.addLayout(grid_layout)

    def apply_and_close(self, theme_name):
        if theme_name == 'Adaptativo':
            self.main_window.settings.setValue("custom_theme", "Adaptativo")
            self.main_window.apply_custom_theme("Default")
        else:
            self.main_window.apply_custom_theme(theme_name)
        self.accept()

    def pick_custom_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.main_window.apply_custom_theme("Custom", color.name())
            self.accept()

class DataTransferDialog(QDialog):
    def __init__(self, parent, available_data_keys=None):
        super().__init__(parent)
        self.is_import = available_data_keys is not None
        self.setWindowTitle("Importar Datos" if self.is_import else "Exportar Datos")

        self.layout = QVBoxLayout(self)
        self.checkboxes = {}

        data_map = {
            "bookmarks": "Favoritos",
            "settings": "Configuración (Página de inicio, buscador, etc.)",
            "history": "Historial de Navegación"
        }

        keys_to_show = available_data_keys if self.is_import else data_map.keys()

        for key in keys_to_show:
            if key in data_map:
                checkbox = QCheckBox(data_map[key])
                checkbox.setChecked(True)
                self.layout.addWidget(checkbox)
                self.checkboxes[key] = checkbox

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.layout.addWidget(button_box)

    def get_selected_keys(self):
        return [key for key, checkbox in self.checkboxes.items() if checkbox.isChecked()]

class SitePermissionsDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Permisos de Sitios")
        self.setMinimumSize(500, 400)

        self.layout = QVBoxLayout(self)

        info_label = QLabel("Aquí puedes ver y modificar los permisos que has concedido o denegado a los sitios web.")
        info_label.setWordWrap(True)
        self.layout.addWidget(info_label)

        self.permissions_table = QTableWidget()
        self.permissions_table.setColumnCount(3)
        self.permissions_table.setHorizontalHeaderLabels(["Sitio", "Permiso", "Estado"])
        self.permissions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.permissions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.permissions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.permissions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.permissions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.permissions_table.setSortingEnabled(True)
        self.layout.addWidget(self.permissions_table)

        button_layout = QHBoxLayout()
        self.delete_button = QPushButton("Eliminar Selección")
        self.delete_button.setToolTip("Elimina los permisos guardados para los sitios seleccionados. Se te volverá a preguntar la próxima vez.")
        self.delete_button.clicked.connect(self._delete_selected_permissions)
        button_layout.addStretch()
        button_layout.addWidget(self.delete_button)
        self.layout.addLayout(button_layout)

        self.feature_key_to_text = {
            "geolocation": "Ubicación",
            "media_audio": "Micrófono",
            "media_video": "Cámara",
            "media_audio_video": "Cámara y Micrófono",
            "notifications": "Notificaciones",
            "mouse_lock": "Bloqueo del Ratón",
        }

        self._populate_table()

    def _populate_table(self):
        self.permissions_table.setSortingEnabled(False)
        self.permissions_table.setRowCount(0)
        saved_permissions = self.main_window.settings.value("site_permissions", {}, type=dict)

        for host, permissions in saved_permissions.items():
            for feature_key, status in permissions.items():
                row = self.permissions_table.rowCount()
                self.permissions_table.insertRow(row)

                host_item = QTableWidgetItem(host)
                host_item.setData(Qt.ItemDataRole.UserRole, host)
                feature_text = self.feature_key_to_text.get(feature_key, feature_key)
                feature_item = QTableWidgetItem(feature_text)
                feature_item.setData(Qt.ItemDataRole.UserRole, feature_key)
                status_combo = QComboBox()
                status_combo.addItems(["Permitir", "Bloquear"])
                status_combo.setCurrentIndex(0 if status == "granted" else 1)
                status_combo.setProperty("host", host)
                status_combo.setProperty("feature_key", feature_key)
                status_combo.currentIndexChanged.connect(self._permission_changed)

                self.permissions_table.setItem(row, 0, host_item)
                self.permissions_table.setItem(row, 1, feature_item)
                self.permissions_table.setCellWidget(row, 2, status_combo)
        
        self.permissions_table.setSortingEnabled(True)

    def _permission_changed(self, index):
        combo_box = self.sender()
        host = combo_box.property("host")
        feature_key = combo_box.property("feature_key")
        new_status = "granted" if index == 0 else "denied"

        saved_permissions = self.main_window.settings.value("site_permissions", {}, type=dict)
        if host in saved_permissions and feature_key in saved_permissions[host]:
            saved_permissions[host][feature_key] = new_status
            self.main_window.settings.setValue("site_permissions", saved_permissions)

    def _delete_selected_permissions(self):
        selected_rows = sorted(list(set(index.row() for index in self.permissions_table.selectedIndexes())), reverse=True)
        if not selected_rows:
            QMessageBox.information(self, "Sin selección", "Selecciona una o más filas para eliminar.")
            return

        reply = QMessageBox.question(self, "Confirmar", f"¿Seguro que quieres eliminar {len(selected_rows)} permiso(s)?\nEl sitio volverá a preguntar la próxima vez.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.No:
            return

        saved_permissions = self.main_window.settings.value("site_permissions", {}, type=dict)

        for row in selected_rows:
            host_item = self.permissions_table.item(row, 0)
            feature_item = self.permissions_table.item(row, 1)
            if not host_item or not feature_item: continue

            host = host_item.data(Qt.ItemDataRole.UserRole)
            feature_key = feature_item.data(Qt.ItemDataRole.UserRole)

            if host in saved_permissions and feature_key in saved_permissions[host]:
                del saved_permissions[host][feature_key]
                if not saved_permissions[host]:
                    del saved_permissions[host]

            self.permissions_table.removeRow(row)

        self.main_window.settings.setValue("site_permissions", saved_permissions)

class PermissionDialog(QDialog):
    def __init__(self, question, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Solicitud de Permiso")
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        layout.addWidget(QLabel(question))
        
        self.remember_checkbox = QCheckBox("Recordar mi decisión para este sitio")
        layout.addWidget(self.remember_checkbox)
        
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Yes | QDialogButtonBox.StandardButton.No)
        self.button_box.button(QDialogButtonBox.StandardButton.Yes).setText("Permitir")
        self.button_box.button(QDialogButtonBox.StandardButton.No).setText("No Permitir")
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def is_remember_checked(self):
        return self.remember_checkbox.isChecked()

class PasswordManager:
    def __init__(self, vault_path, master_password):
        self.vault_path = vault_path
        self._load_vault(master_password)
        self.master_password = master_password

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def _load_vault(self, master_password):
        with open(self.vault_path, "rb") as f:
            encrypted_data = f.read()
        
        salt = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)
        
        decrypted_json = fernet.decrypt(encrypted_content)
        self.data = json.loads(decrypted_json)

        if self.data.get("check") != "WemphixVaultOK":
            raise ValueError("Vault check failed. Data might be corrupt.")

    def _save_vault(self):
        json_data = json.dumps(self.data).encode()
        
        salt = base64.urlsafe_b64decode(self.data["salt"].encode())
        key = self._derive_key(self.master_password, salt)
        fernet = Fernet(key)
        encrypted_content = fernet.encrypt(json_data)
        
        with open(self.vault_path, "wb") as f:
            f.write(salt + encrypted_content)

    @staticmethod
    def create_new_vault(path, master_password):
        salt = os.urandom(16)
        vault_data = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "check": "WemphixVaultOK",
            "logins": [],
        }
        
        pm = PasswordManager.__new__(PasswordManager)
        pm.vault_path = path
        pm.data = vault_data
        pm.master_password = master_password
        pm._save_vault()
        return pm

    def get_all_logins(self):
        return self.data.get("logins", [])

    def save_password(self, url, username, password):
        # Remove existing entry for the same url/username
        self.data["logins"] = [
            login for login in self.data["logins"]
            if not (login["url"] == url and login["username"] == username)
        ]
        self.data["logins"].append({"url": url, "username": username, "password": password})
        self._save_vault()

    def delete_password(self, url, username):
        self.data["logins"] = [
            login for login in self.data["logins"]
            if not (login["url"] == url and login["username"] == username)
        ]
        self._save_vault()

    def find_logins_for_url(self, url_origin):
        """Finds all saved usernames for a given URL origin."""
        return [login["username"] for login in self.data.get("logins", []) if login.get("url") == url_origin]

    def get_password_for_login(self, url_origin, username):
        """Gets the password for a specific URL origin and username."""
        for login in self.data.get("logins", []):
            if login.get("url") == url_origin and login.get("username") == username:
                return login.get("password", "")
        return ""

class MasterPasswordDialog(QDialog):
    def __init__(self, parent, is_creating=False):
        super().__init__(parent)
        self.setWindowTitle("Contraseña Maestra")
        self.layout = QVBoxLayout(self)

        if is_creating:
            self.layout.addWidget(QLabel("Crea una contraseña maestra para proteger tu bóveda:"))
            self.pass_input = QLineEdit()
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            
            form = QFormLayout()
            form.addRow("Nueva Contraseña:", self.pass_input)
            form.addRow("Confirmar Contraseña:", self.confirm_input)
            self.layout.addLayout(form)

            suggestion_group = QGroupBox("Sugerencia de Contraseña Segura")
            suggestion_layout = QVBoxLayout(suggestion_group)

            self.suggested_password_label = QLabel()
            self.suggested_password_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            suggestion_layout.addWidget(self.suggested_password_label)

            suggestion_buttons_layout = QHBoxLayout()
            suggest_new_btn = QPushButton("Sugerir Nueva")
            suggest_new_btn.clicked.connect(self._generate_suggested_password)
            use_suggestion_btn = QPushButton("Usar Sugerencia")
            use_suggestion_btn.clicked.connect(self._use_suggestion)
            suggestion_buttons_layout.addWidget(suggest_new_btn)
            suggestion_buttons_layout.addWidget(use_suggestion_btn)
            suggestion_layout.addLayout(suggestion_buttons_layout)

            self.layout.addWidget(suggestion_group)
            self._generate_suggested_password()

        else:
            self.layout.addWidget(QLabel("Introduce tu contraseña maestra para desbloquear:"))
            self.pass_input = QLineEdit()
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.layout.addWidget(self.pass_input)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.layout.addWidget(button_box)

    def _generate_suggested_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            # Generar una contraseña de 20 caracteres para alta seguridad
            password = ''.join(secrets.choice(alphabet) for i in range(20))
            # Asegurar que contenga todos los tipos de caracteres
            if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(c in string.punctuation for c in password)):
                break
        self.suggested_password_label.setText(f"Sugerencia: <b>{password}</b>")
        self.suggested_password = password

    def _use_suggestion(self):
        if hasattr(self, 'suggested_password'):
            self.pass_input.setText(self.suggested_password)
            if hasattr(self, 'confirm_input'):
                self.confirm_input.setText(self.suggested_password)

    def get_password(self):
        return self.pass_input.text()

    def accept(self):
        if hasattr(self, 'confirm_input'):
            if self.pass_input.text() != self.confirm_input.text():
                QMessageBox.warning(self, "Error", "Las contraseñas no coinciden.")
                return
            if not self.pass_input.text():
                QMessageBox.warning(self, "Error", "La contraseña no puede estar vacía.")
                return
        super().accept()

class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Generador de Contraseña")
        self.layout = QVBoxLayout(self)

        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.layout.addWidget(self.password_display)

        button_layout = QHBoxLayout()
        self.regenerate_btn = QPushButton("Generar de Nuevo")
        self.copy_btn = QPushButton("Copiar")
        button_layout.addWidget(self.regenerate_btn)
        button_layout.addWidget(self.copy_btn)
        self.layout.addLayout(button_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.button(QDialogButtonBox.StandardButton.Ok).setText("Usar Contraseña")
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.layout.addWidget(button_box)

        self.regenerate_btn.clicked.connect(self._generate_password)
        self.copy_btn.clicked.connect(self._copy_password)
        self._generate_password()

    def _generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        self.password_display.setText(password)

    def _copy_password(self):
        QApplication.clipboard().setText(self.get_password())

    def get_password(self):
        return self.password_display.text()

class ManagePasswordsDialog(QDialog):
    def __init__(self, parent: "Navegador"):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Contraseñas Guardadas")
        self.setMinimumSize(600, 400)
        self.layout = QVBoxLayout(self)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Sitio Web", "Usuario", "Contraseña"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.layout.addWidget(self.table)

        button_layout = QHBoxLayout()
        self.show_btn = QPushButton("Mostrar")
        self.copy_btn = QPushButton("Copiar Contraseña")
        self.delete_btn = QPushButton("Eliminar")
        button_layout.addStretch()
        button_layout.addWidget(self.show_btn)
        button_layout.addWidget(self.copy_btn)
        button_layout.addWidget(self.delete_btn)
        self.layout.addLayout(button_layout)

        self.show_btn.clicked.connect(self._toggle_show_password)
        self.copy_btn.clicked.connect(self._copy_password)
        self.delete_btn.clicked.connect(self._delete_password)

        self._populate_table()

    def _populate_table(self):
        logins = self.main_window.password_manager.get_all_logins()
        self.table.setRowCount(len(logins))
        for i, login in enumerate(logins):
            self.table.setItem(i, 0, QTableWidgetItem(login["url"]))
            self.table.setItem(i, 1, QTableWidgetItem(login["username"]))
            password_item = QTableWidgetItem("••••••••")
            password_item.setData(Qt.ItemDataRole.UserRole, login["password"])
            self.table.setItem(i, 2, password_item)

    def _toggle_show_password(self):
        selected = self.table.selectedItems()
        if not selected: return
        row = selected[0].row()
        item = self.table.item(row, 2)
        if item.text() == "••••••••":
            item.setText(item.data(Qt.ItemDataRole.UserRole))
        else:
            item.setText("••••••••")

    def _copy_password(self):
        selected = self.table.selectedItems()
        if not selected: return
        row = selected[0].row()
        password = self.table.item(row, 2).data(Qt.ItemDataRole.UserRole)
        QApplication.clipboard().setText(password)

    def _delete_password(self):
        selected = self.table.selectedItems()
        if not selected: return
        row = selected[0].row()
        url = self.table.item(row, 0).text()
        username = self.table.item(row, 1).text()
        
        reply = QMessageBox.question(self, "Confirmar", f"¿Seguro que quieres eliminar la contraseña de '{username}' en {url}?")
        if reply == QMessageBox.StandardButton.Yes:
            self.main_window.password_manager.delete_password(url, username)
            self.table.removeRow(row)

def main():
    
    server_name = "WemphixBrowserInstance_v1.3"

    app = QApplication(sys.argv)

    
    socket = QLocalSocket()
    socket.connectToServer(server_name)

    
    if socket.waitForConnected(500):
        print("INFO: Wemphix ya está en ejecución. Enviando argumentos a la instancia existente.")
        arguments = "\n".join(sys.argv[1:]).encode('utf-8')
        if arguments:
            socket.write(arguments)
            socket.flush()
            socket.waitForBytesWritten(1000)
        socket.disconnectFromServer()
        sys.exit(0)

    server = QLocalServer()
    QLocalServer.removeServer(server_name)
    if not server.listen(server_name):
        QMessageBox.critical(None, "Error de Wemphix",
                             f"No se pudo iniciar el servidor local: {server.errorString()}.\n"
                             "Puede que otra instancia esté bloqueada. Cierra todos los procesos de Wemphix y vuelve a intentarlo.")
        sys.exit(1)

    print("INFO: Iniciando nueva instancia de Wemphix.")

    def cleanup_server():
        server.close()
    app.aboutToQuit.connect(cleanup_server)

    settings = QSettings("WemphixOrg", "Wemphix")
    apply_app_theme(settings)

    ventana = Navegador()

    def handle_new_instance():
        client_connection = server.nextPendingConnection()

        def read_from_socket():
            data = client_connection.readAll().data().decode('utf-8')
            urls = [url for url in data.split('\n') if url]
            print(f"INFO: Nueva instancia solicitó abrir: {urls}")
            for url in urls:
                if url.startswith("http:") or url.startswith("https:") or os.path.exists(url):
                    ventana.agregar_pestana(url, focus=True)
            ventana.activateWindow()
            ventana.raise_()
            client_connection.disconnected.connect(client_connection.deleteLater)
            client_connection.disconnectFromServer()

        client_connection.readyRead.connect(read_from_socket)

    server.newConnection.connect(handle_new_instance)

    initial_urls = [arg for arg in sys.argv[1:] if arg.startswith("http:") or arg.startswith("https:") or os.path.exists(arg)]

    ventana._restore_session(open_default_if_empty=not initial_urls)

    if initial_urls:
        for url in initial_urls:
            ventana.agregar_pestana(url, focus=True)

    ventana.show()
    exit_code = app.exec()

    if ventana.about_to_clear_profile and os.path.exists(ventana.profile_path):
        try:
            shutil.rmtree(ventana.profile_path)
            print(f"Perfil de usuario borrado con éxito: {ventana.profile_path}")
        except OSError as e:
            print(f"Error al borrar el perfil. Puede que necesites borrarlo manualmente:\n{ventana.profile_path}\nError: {e}")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
