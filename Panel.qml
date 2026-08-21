import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root

  moduleName: "ucmz851.omasecurity"
  ipcTarget: "ucmz851.omasecurity"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.45)
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
  property string selectedCategoryKey: "all"
  property string copiedNotice: ""

  property int cursorIndex: 0

  readonly property var categoryList: [
    { label: "All", key: "all" },
    { label: "Plugins", key: "Plugin Health" },
    { label: "System", key: "System Security" },
    { label: "Network", key: "Network" },
    { label: "Auth", key: "Authentication" }
  ]

  readonly property var filteredAudits: {
    if (!audits || audits.length === 0) return []
    if (selectedCategoryKey === "all") return audits
    var out = []
    for (var i = 0; i < audits.length; i++) {
      if (audits[i].category === selectedCategoryKey) {
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

  function getSeverityColor(sev) {
    if (sev === "CRITICAL") return urgent
    if (sev === "HIGH") return urgent
    if (sev === "MEDIUM") return Color.accent
    return dim
  }

  function copyToClipboard(text) {
    if (!text) return
    Quickshell.execDetached(["wl-copy", "--", text])
    root.copiedNotice = text
    noticeTimer.restart()
  }

  function refresh() {
    if (auditProc.running) return
    isScanning = true
    auditProc.running = true
  }

  function parseAuditOutput(text) {
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

  onOpenedChanged: {
    if (opened) {
      root.cursorIndex = 0
      Qt.callLater(function() {
        if (keyCatcher) keyCatcher.forceActiveFocus()
        if (auditList) {
          auditList.contentY = 0
          auditList.positionViewAtBeginning()
        }
      })
    }
  }

  Timer {
    id: scanTimer
    interval: 900000
    running: true
    repeat: true
    onTriggered: root.refresh()
  }

  Timer {
    id: noticeTimer
    interval: 2500
    running: false
    repeat: false
    onTriggered: root.copiedNotice = ""
  }

  Process {
    id: auditProc
    command: ["python3", Qt.resolvedUrl("scripts/audit.py").toString().replace(/^file:\/\//, "")]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.parseAuditOutput(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) console.log("omasecurity stderr:", text)
    }
    onExited: function(exitCode) {
      root.isScanning = false
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

    contentWidth: panel.fittedContentWidth(Style.space(460))
    contentHeight: panel.fittedContentHeight(mainLayout.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent

      onMoveRequested: function(dx, dy) {
        if (dy !== 0 && root.filteredAudits.length > 0) {
          var nextIdx = Math.max(0, Math.min(root.filteredAudits.length - 1, root.cursorIndex + dy))
          root.cursorIndex = nextIdx
          if (auditList) {
            auditList.currentIndex = nextIdx
            auditList.positionViewAtIndex(nextIdx, dy > 0 ? ListView.End : ListView.Beginning)
          }
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
        id: mainLayout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(10)

        // ------------------ HERO HEADER ------------------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroShield.implicitHeight, heroLabels.implicitHeight)

          Text {
            textFormat: Text.PlainText
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
                textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
              textFormat: Text.PlainText
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
            tooltipText: root.isScanning ? "Scanning system..." : "Rescan Now"
            foreground: root.isScanning ? Color.accent : root.foreground
            rotation: 0
            onClicked: root.refresh()

            RotationAnimation on rotation {
              from: 0
              to: 360
              duration: 800
              loops: Animation.Infinite
              running: root.isScanning
            }
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
            textFormat: Text.PlainText
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
            model: root.categoryList
            delegate: BorderSurface {
              readonly property bool isSelected: root.selectedCategoryKey === modelData.key
              implicitWidth: catLabel.implicitWidth + Style.space(14)
              implicitHeight: catLabel.implicitHeight + Style.space(8)
              radius: Style.cornerRadius
              color: isSelected ? Style.selectedFillFor(root.foreground, root.foreground) : "transparent"
              borderSpec: isSelected
                ? Border.controlSpec("selected", Color.accent, Color.accent)
                : Border.controlSpec("normal", root.dim, Color.accent)

              Text {
                textFormat: Text.PlainText
                id: catLabel
                anchors.centerIn: parent
                text: modelData.label
                color: isSelected ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: isSelected
              }

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.selectedCategoryKey = modelData.key
                  root.cursorIndex = 0
                  if (auditList) {
                    auditList.contentY = 0
                    auditList.positionViewAtBeginning()
                  }
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
          height: Style.space(380)
          clip: true
          spacing: Style.space(8)
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          interactive: true
          model: root.filteredAudits
          currentIndex: root.cursorIndex

          ScrollBar.vertical: ScrollBar {
            id: vbar
            policy: ScrollBar.AsNeeded
            interactive: true
            width: Style.space(5)
            anchors.right: parent.right

            contentItem: Rectangle {
              implicitWidth: Style.space(5)
              radius: Style.cornerRadius
              color: vbar.pressed ? Color.accent : (vbar.hovered ? root.foreground : Qt.darker(root.foreground, 1.8))
            }
          }

          delegate: BorderSurface {
            id: itemCard
            width: auditList.width - Style.space(12)
            implicitHeight: cardColumn.implicitHeight + Style.space(18)
            radius: Style.cornerRadius

            readonly property bool hasCursor: root.cursorIndex === index
            readonly property bool isPassed: modelData.passed === true
            readonly property color cardBorderColor: isPassed ? root.foreground : (modelData.score === 0 ? root.urgent : Color.accent)

            color: hasCursor ? Style.hoverFillFor(root.foreground, root.foreground) : "transparent"
            borderSpec: hasCursor
              ? Border.controlSpec("hover-cursor", cardBorderColor, cardBorderColor)
              : Border.controlSpec("normal", root.dim, cardBorderColor)

            Column {
              id: cardColumn
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.top: parent.top
              anchors.margins: Style.space(9)
              spacing: Style.space(6)

              // Card Header: Icon, Title, and Score Badge
              Item {
                width: parent.width
                implicitHeight: Math.max(statusIcon.implicitHeight, titleText.implicitHeight, scoreBadge.implicitHeight)

                Text {
                  textFormat: Text.PlainText
                  id: statusIcon
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  text: itemCard.isPassed ? "" : ""
                  color: itemCard.isPassed ? Color.accent : (modelData.score === 0 ? root.urgent : Color.accent)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                }

                BorderSurface {
                  id: scoreBadge
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  implicitWidth: scoreText.implicitWidth + Style.space(8)
                  implicitHeight: scoreText.implicitHeight + Style.space(2)
                  color: "transparent"
                  borderSpec: Border.none()

                  Text {
                    textFormat: Text.PlainText
                    id: scoreText
                    anchors.centerIn: parent
                    text: (itemCard.isPassed ? "+" : "") + modelData.score + "/" + modelData.max_score + " pts"
                    color: itemCard.isPassed ? root.dim : (modelData.score === 0 ? root.urgent : Color.accent)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                }

                Text {
                  id: titleText
                  textFormat: Text.PlainText
                  anchors.left: statusIcon.right
                  anchors.leftMargin: Style.space(8)
                  anchors.right: scoreBadge.left
                  anchors.rightMargin: Style.space(8)
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData.title
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  elide: Text.ElideRight
                }
              }

              // Card Description
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: modelData.description
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.Wrap
              }

              // Flagged Plugin Deep Findings (if present)
              Repeater {
                model: modelData.flagged_items || []
                delegate: BorderSurface {
                  width: parent.width
                  implicitHeight: flaggedCol.implicitHeight + Style.space(10)
                  color: Style.hoverFillFor(root.urgent, root.urgent)
                  borderSpec: Border.controlSpec("normal", root.urgent, root.urgent)
                  radius: Style.cornerRadius

                  Column {
                    id: flaggedCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: Style.space(6)
                    spacing: Style.space(2)

                    Row {
                      spacing: Style.space(6)
                      BorderSurface {
                        implicitWidth: sevText.implicitWidth + Style.space(6)
                        implicitHeight: sevText.implicitHeight + Style.space(2)
                        color: "transparent"
                        borderSpec: Border.controlSpec("normal", root.getSeverityColor(modelData.severity), root.getSeverityColor(modelData.severity))
                        radius: Style.cornerRadius

                        Text {
                          textFormat: Text.PlainText
                          id: sevText
                          anchors.centerIn: parent
                          text: modelData.severity
                          color: root.getSeverityColor(modelData.severity)
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          font.bold: true
                        }
                      }

                      Text {
                        textFormat: Text.PlainText
                        text: modelData.title
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }
                    }

                    Text {
                      width: parent.width
                      textFormat: Text.PlainText
                      text: "File: " + modelData.file + ":" + modelData.line
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      elide: Text.ElideMiddle
                    }

                    Text {
                      width: parent.width
                      textFormat: Text.PlainText
                      text: "`" + modelData.snippet + "`"
                      color: root.urgent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                      wrapMode: Text.Wrap
                    }
                  }
                }
              }

              // Recommendation text if not passed
              Text {
                textFormat: Text.PlainText
                visible: modelData.recommendation !== null && modelData.recommendation !== undefined && modelData.recommendation !== ""
                width: parent.width
                text: "Recommendation: " + (modelData.recommendation || "")
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.Wrap
              }

              // Fix Command Box with robust wrapping & padding
              BorderSurface {
                visible: modelData.fix_cmd !== null && modelData.fix_cmd !== undefined && modelData.fix_cmd !== ""
                width: parent.width
                implicitHeight: fixRow.implicitHeight + Style.space(12)
                color: Style.hoverFillFor(root.foreground, root.foreground)
                borderSpec: Border.controlSpec("normal", root.dim, Color.accent)
                radius: Style.cornerRadius

                RowLayout {
                  id: fixRow
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: Style.space(6)
                  spacing: Style.space(6)

                  Text {
                    id: fixText
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: "$ " + (modelData.fix_cmd || "")
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    wrapMode: Text.WrapAnywhere
                  }

                  PanelActionButton {
                    id: copyBtn
                    Layout.alignment: Qt.AlignRight | Qt.AlignTop
                    iconText: ""
                    tooltipText: "Copy Command"
                    foreground: Color.accent
                    onClicked: root.copyToClipboard(modelData.fix_cmd)
                  }
                }
              }
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              propagateComposedEvents: true
              onWheel: function(wheel) { wheel.accepted = false }
              onClicked: function(mouse) {
                root.cursorIndex = index
                if (modelData.fix_cmd) root.copyToClipboard(modelData.fix_cmd)
              }
            }
          }
        }

        // ------------------ FOOTER ------------------
        Text {
          textFormat: Text.PlainText
          width: parent.width
          text: "Tip: Scroll with mouse or press ↑ / ↓ to navigate · Click any command to copy · 'R' to rescan"
          color: Qt.darker(root.dim, 1.3)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          horizontalAlignment: Text.AlignHCenter
          wrapMode: Text.Wrap
        }
      }
    }
  }
}
