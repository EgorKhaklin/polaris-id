{{- define "polaris.fullname" -}}{{ .Release.Name }}{{- end -}}
{{- define "polaris.labels" -}}
app.kubernetes.io/name: polaris
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "polaris.selector" -}}
app.kubernetes.io/name: polaris
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "polaris.secretName" -}}{{ default (printf "%s-secrets" (include "polaris.fullname" .)) .Values.secrets.existingSecret }}{{- end -}}
{{/* restricted Pod Security Standard, pod level */}}
{{- define "polaris.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .gid }}
fsGroup: {{ .gid }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{/* restricted Pod Security Standard, container level */}}
{{- define "polaris.containerSecurity" -}}
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
{{- end -}}
{{/* the same, and the image's own filesystem read-only (lab record 017, phase 5): the
     container writes only to the volumes it mounts */}}
{{- define "polaris.containerSecurityReadOnly" -}}
{{ include "polaris.containerSecurity" . }}
readOnlyRootFilesystem: true
{{- end -}}
