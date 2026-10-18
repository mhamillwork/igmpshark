{{- define "igmpshark.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "igmpshark.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "igmpshark.name" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
