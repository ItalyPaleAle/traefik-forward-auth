<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>{{ .Title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{{ .BaseUrl }}/style.css">
</head>

<style>
@layer theme {
    :root {
        --bg-image-lg: url({{ .BackgroundLarge }});
        --bg-image-md: url({{ .BackgroundMedium }});
    }
}
</style>

<body class="flex flex-col">
    {{ if .LogoutBanner }}
    <div class="alert" role="alert">
        <div class="alert-container">
            <div class="inline-flex items-center justify-center w-5 h-5 text-green-500 bg-green-100 rounded-lg lg:w-7 lg:h-7 shrink-0 dark:bg-green-800 dark:text-green-200">
                <svg class="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                </svg>
                <span class="sr-only">Checkmark icon</span>
            </div>
            <div class="text-sm font-normal ms-3">You've been logged out. You can sign back in using the form below.</div>
        </div>
    </div>
    {{ end }}
    <div class="layout grow">
        <div class="layout-container">
            <div class="layout-content">
                <div class="layout-content-main">
                    <h1 class="pb-2 text-2xl md:text-3xl md:pb-4">{{ .Title }}</h1>
                    <div class="flex flex-col items-center justify-center space-y-2">
                        {{ range .Providers }}
                        <a href="{{ .Href }}" class="provider-button tfa-{{ .Color }}">
                            <span class="provider-button-inner">
                                {{ with .Svg }}{{ . }}{{ end }}
                                {{ .DisplayName }}
                            </span>
                        </a>
                        {{ end }}
                    </div>
                </div>
                <div class="layout-content-side"></div>
            </div>
        </div>
    </div>
</body>

</html>
