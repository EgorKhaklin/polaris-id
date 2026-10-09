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

{{/* Lab record 017 (gate row OP-7): a replicated component spread across nodes (never two on one node
     while another schedulable node is free) and, as far as the cluster allows, across zones. One
     schedulable node is one domain, so a single-node cluster still schedules; a tainted node (a control
     plane) is not a domain. Call with (list "component" $). */}}
{{- define "polaris.spread" -}}
{{- $component := index . 0 -}}
{{- $root := index . 1 -}}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    nodeTaintsPolicy: Honor
    labelSelector:
      matchLabels:
        {{- include "polaris.selector" $root | nindent 8 }}
        app.kubernetes.io/component: {{ $component }}
  - maxSkew: 1
    topologyKey: {{ $root.Values.spread.zoneKey }}
    whenUnsatisfiable: ScheduleAnyway
    nodeTaintsPolicy: Honor
    labelSelector:
      matchLabels:
        {{- include "polaris.selector" $root | nindent 8 }}
        app.kubernetes.io/component: {{ $component }}
{{- end -}}

{{/* Lab record 017 (gate row OP-7): a pod Kubernetes may move is moved off a node that stopped answering
     after spread.evictAfterSeconds, not the default 300 s. */}}
{{- define "polaris.fastEviction" -}}
tolerations:
  - {key: node.kubernetes.io/unreachable, operator: Exists, effect: NoExecute, tolerationSeconds: {{ .Values.spread.evictAfterSeconds }}}
  - {key: node.kubernetes.io/not-ready, operator: Exists, effect: NoExecute, tolerationSeconds: {{ .Values.spread.evictAfterSeconds }}}
{{- end -}}

{{/* Lab record 017 (gate row OP-7): a voluntary disruption (a node drained) leaves one pod serving. */}}
{{- define "polaris.pdb" -}}
{{- $component := index . 0 -}}
{{- $root := index . 1 -}}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "polaris.fullname" $root }}-{{ $component }}
  labels:
    {{- include "polaris.labels" $root | nindent 4 }}
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      {{- include "polaris.selector" $root | nindent 6 }}
      app.kubernetes.io/component: {{ $component }}
{{- end -}}
