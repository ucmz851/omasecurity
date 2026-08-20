import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root

  moduleName: "omasecurity"
  ipcTarget: "omasecurity"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.5)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Security audit state
  property int score: 100
  property string grade: "A"
  property string statusLabel: "Scanning..."
  property string statusColor: "normal"
  property int failedCount: 0
  property int totalChecks: 0
  property var audits: []
  property string lastScanTime: ""
  property bool isScanning: false
  property string selectedCategory: "All"
  property string copiedNotice: ""

  property int cursorIndex: 0

  readonly property var filteredAudits: {
    if (!audits || audits.length === 0) return []
    if (selectedCategory === "All") return audits
    var out = []
    for (var i = 0; i < audits.length; i++) {
      if (audits[i].category === selectedCategory) {
        out.push(audits[i])
      }
    }
    return out
  }

  function getStatusColorToken(type) {
    if (type === "good") return Color.accent
    if (type === "warning") return Color.accent
    if (type === "urgent") return urgent
    return foreground
  }

  function copyToClipboard(text) {
    if (!text) return
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(text) + " | wl-copy"])
    root.copiedNotice = text
    noticeTimer.restart()
  }

  function refresh() {
    if (isScanning) return
    isScanning = true
    auditProc.running = true
  }

  function parseAuditOutput(text) {
    isScanning = false
    if (!text || text.trim() === "") return
    try {
      var data = JSON.parse(text)
      root.score = data.score !== undefined ? data.score : 100
      root.grade = data.grade || "A"
      root.statusLabel = data.statusLabel || "System Hardened"
      root.statusColor = data.statusColor || "normal"
      root.failedCount = data.failedCount || 0
      root.totalChecks = data.totalChecks || 0
      root.audits = data.audits || []
      root.lastScanTime = data.timestamp || ""
    } catch (e) {
      console.log("omasecurity JSON parse error:", e)
    }
  }

  // Periodic rescan timer: every 15 minutes
  Timer {
    id: scanTimer
    interval: 900000
    running: true
    repeat: true
    onTriggered: root.refresh()
  }

  Timer {
    id: noticeTimer
    interval: 3000
    running: false
    repeat: false
    onTriggered: root.copiedNotice = ""
  }

  Process {
    id: auditProc
    command: ["python3", Quickshell.env("HOME") + "/.config/omarchy/plugins/omasecurity/scripts/audit.py"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.parseAuditOutput(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) console.log("omasecurity stderr:", text)
    }
  }

  Component.onCompleted: root.refresh()

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher

    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(Style.space(520))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent

      onMoveRequested: function(dx, dy) {
        if (dy !== 0 && root.filteredAudits.length > 0) {
          root.cursorIndex = Math.max(0, Math.min(root.filteredAudits.length - 1, root.cursorIndex + dy))
        }
      }
      onActivateRequested: {
        if (root.filteredAudits.length > 0 && root.cursorIndex < root.filteredAudits.length) {
          var item = root.filteredAudits[root.cursorIndex]
          if (item && item.fix_cmd) root.copyToClipboard(item.fix_cmd)
        }
      }
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") root.refresh()
      }

      Column {
        anchors.fill: parent
        spacing: Style.space(12)

        // ------------------ HERO SECTION ------------------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroShield.implicitHeight, heroLabels.implicitHeight)

          Text {
            id: heroShield
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: "󰒃"
            color: root.getStatusColorToken(root.statusColor)
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
          }

          Column {
            id: heroLabels
            anchors.left: heroShield.right
            anchors.leftMargin: Style.space(12)
            anchors.right: heroAction.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Row {
              spacing: Style.space(8)
              Text {
                text: "Security Score: " + root.score + "%"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }

              BorderSurface {
                implicitWidth: gradeText.implicitWidth + Style.space(10)
                implicitHeight: gradeText.implicitHeight + Style.space(4)
                anchors.verticalCenter: parent.verticalCenter
                color: "transparent"
                borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)
                radius: Style.cornerRadius

                Text {
                  id: gradeText
                  anchors.centerIn: parent
                  text: "Grade " + root.grade
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }
            }

            Text {
              text: root.statusLabel + " · " + (root.lastScanTime ? "Last scan: " + root.lastScanTime : "Ready")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
            }
          }

          PanelActionButton {
            id: heroAction
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            iconText: ""
            tooltipText: "Rescan Now"
            foreground: root.foreground
            onClicked: root.refresh()
          }
        }

        // ------------------ COPIED NOTICE BANNER ------------------
        BorderSurface {
          visible: root.copiedNotice !== ""
          width: parent.width
          implicitHeight: noticeText.implicitHeight + Style.space(8)
          color: "transparent"
          borderSpec: Border.controlSpec("focus", Color.accent, Color.accent)
          radius: Style.cornerRadius

          Text {
            id: noticeText
            anchors.centerIn: parent
            text: "Copied fix command: " + root.copiedNotice
            color: Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            elide: Text.ElideMiddle
            width: parent.width - Style.space(16)
            horizontalAlignment: Text.AlignHCenter
          }
        }

        // ------------------ CATEGORY TABS ------------------
        Row {
          width: parent.width
          spacing: Style.space(6)

          Repeater {
            model: ["All", "Network", "Plugin Health", "Authentication", "Desktop Security"]
            delegate: BorderSurface {
              readonly property bool isSelected: root.selectedCategory === modelData
              implicitWidth: catLabel.implicitWidth + Style.space(12)
              implicitHeight: catLabel.implicitHeight + Style.space(6)
              radius: Style.cornerRadius
              color: isSelected ? Style.selectedFillFor(root.foreground, root.foreground) : "transparent"
              borderSpec: isSelected
                ? Border.controlSpec("selected", Color.accent, Color.accent)
                : Border.controlSpec("normal", root.foreground, Color.accent)

              Text {
                id: catLabel
                anchors.centerIn: parent
                text: modelData
                color: isSelected ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: isSelected
              }

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.selectedCategory = modelData
                  root.cursorIndex = 0
                }
              }
            }
          }
        }

        PanelSeparator {
          width: parent.width
        }

        // ------------------ AUDIT ITEMS LIST ------------------
        ListView {
          id: auditList
          width: parent.width
          height: Style.space(290)
          clip: true
          spacing: Style.space(8)
          model: root.filteredAudits

          delegate: BorderSurface {
            id: itemCard
            width: auditList.width
            implicitHeight: cardContent.implicitHeight + Style.space(12)
            radius: Style.cornerRadius

            readonly property bool hasCursor: root.cursorIndex === index
            readonly property bool isPassed: modelData.passed === true
            readonly property color cardBorderColor: isPassed ? root.foreground : (modelData.score === 0 ? root.urgent : Color.accent)

            color: hasCursor ? Style.hoverFillFor(root.foreground, root.foreground) : "transparent"
            borderSpec: hasCursor
              ? Border.controlSpec("hover-cursor", cardBorderColor, cardBorderColor)
              : Border.controlSpec("normal", root.dim, cardBorderColor)

            Column {
              id: cardContent
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.top: parent.top
              anchors.margins: Style.space(8)
              spacing: Style.space(4)

              Row {
                width: parent.width
                spacing: Style.space(8)

                Text {
                  text: itemCard.isPassed ? "" : ""
                  color: itemCard.isPassed ? Color.accent : (modelData.score === 0 ? root.urgent : Color.accent)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  anchors.verticalCenter: parent.verticalCenter
                }

                Text {
                  text: modelData.title
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  elide: Text.ElideRight
                  width: parent.width - scoreBadge.implicitWidth - Style.space(32)
                  anchors.verticalCenter: parent.verticalCenter
                }

                Item { Layout.fillWidth: true; height: 1 }

                BorderSurface {
                  id: scoreBadge
                  implicitWidth: scoreText.implicitWidth + Style.space(8)
                  implicitHeight: scoreText.implicitHeight + Style.space(2)
                  color: "transparent"
                  borderSpec: Border.none()
                  anchors.verticalCenter: parent.verticalCenter

                  Text {
                    id: scoreText
                    anchors.centerIn: parent
                    text: (itemCard.isPassed ? "+" : "") + modelData.score + "/" + modelData.max_score + " pts"
                    color: itemCard.isPassed ? root.dim : (modelData.score === 0 ? root.urgent : Color.accent)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }

              Text {
                width: parent.width
                text: modelData.description
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.Wrap
              }

              // Flagged items list if present
              Repeater {
                model: modelData.flagged_items || []
                delegate: Text {
                  width: parent.width
                  text: "• " + modelData.plugin + " (" + modelData.file + "): " + modelData.reason
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.Wrap
                }
              }

              // Fix Command Box if present
              BorderSurface {
                visible: modelData.fix_cmd !== null && modelData.fix_cmd !== undefined && modelData.fix_cmd !== ""
                width: parent.width
                implicitHeight: fixRow.implicitHeight + Style.space(6)
                color: Style.hoverFillFor(root.foreground, root.foreground)
                borderSpec: Border.controlSpec("normal", root.dim, Color.accent)
                radius: Style.cornerRadius

                Row {
                  id: fixRow
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.margins: Style.space(6)
                  spacing: Style.space(6)

                  Text {
                    text: "$ " + (modelData.fix_cmd || "")
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    elide: Text.ElideRight
                    width: parent.width - copyBtn.implicitWidth - Style.space(12)
                    anchors.verticalCenter: parent.verticalCenter
                  }

                  PanelActionButton {
                    id: copyBtn
                    iconText: ""
                    tooltipText: "Copy Command"
                    foreground: Color.accent
                    onClicked: root.copyToClipboard(modelData.fix_cmd)
                    anchors.verticalCenter: parent.verticalCenter
                  }
                }
              }
            }

            MouseArea {
              anchors.fill: parent
              onClicked: {
                root.cursorIndex = index
                if (modelData.fix_cmd) root.copyToClipboard(modelData.fix_cmd)
              }
            }
          }
        }

        // ------------------ FOOTER ------------------
        Text {
          width: parent.width
          text: "Tip: Press 'R' to rescan, or click any command to copy."
          color: Qt.darker(root.dim, 1.3)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          horizontalAlignment: Text.AlignHCenter
        }
      }
    }
  }
}
