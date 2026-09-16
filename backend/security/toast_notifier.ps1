
param(
    [string]$Title = "AWSSecurity Alert",
    [string]$Message = "Secondary device requesting access"
)
try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $xml = [xml]$template.GetXml()
    $texts = $xml.GetElementsByTagName('text')
    $texts[0].AppendChild($xml.CreateTextNode($Title)) | Out-Null
    $texts[1].AppendChild($xml.CreateTextNode($Message)) | Out-Null
    $toastXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $toastXml.LoadXml($xml.OuterXml)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($toastXml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AWSSecurity").Show($toast)
} catch {
    # Fail silently if notifications are disabled in Windows settings
}
