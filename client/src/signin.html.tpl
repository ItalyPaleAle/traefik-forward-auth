<!DOCTYPE html>
<html>

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

<body class="flex flex-col bg-gray-100 dark:bg-gray-900 h-dvh">
    {{ if .LogoutBanner }}
    <div class="w-full p-1 pb-1.5 lg:p-2 lg:pb-2" role="alert">
        <div class="flex items-center w-full px-2 py-1.5 text-gray-700 rounded-md lg:px-4 lg:py-2 lg:rounded-lg bg-green-50 dark:text-gray-100 dark:bg-green-900">
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
    <div class="
        bg-(image:--bg-image-md) md:bg-(image:--bg-image-lg) lg:bg-none
        bg-cover bg-center p-1 grow">
        <div class="flex flex-row items-center justify-center flex-none h-full lg:block">
            <div class="flex flex-col lg:flex-row lg:h-full lg:bg-white rounded-xl lg:rounded-r-4xl lg:rounded-l-md backdrop-blur-sm lg:backdrop-blur-none bg-white/90 dark:bg-gray-800/85">
                <div class="flex flex-col items-center justify-center flex-none px-10 py-6 space-y-2 md:py-8 md:px-14 lg:basis-2xl">
                    <h1 class="pb-2 text-2xl text-gray-900 dark:text-white md:text-3xl md:pb-4">{{ .Title }}</h1>
                    <div class="flex flex-col items-center justify-center space-y-2">
                        {{ range .Providers }}
                        <a href="{{ .Href }}" class="relative w-full flex-1 flex-grow inline-flex items-center justify-center p-0.5 text-sm font-medium rounded-lg group bg-gradient-to-br {{ .Color }}">
                            <span class="relative text-sm md:text-base w-full inline-flex items-center px-3 py-2 md:px-5 md:py-2.5 transition-all ease-in duration-75 bg-white dark:bg-gray-900 rounded-md group-hover:bg-transparent group-hover:dark:bg-transparent">
                                {{ with .Svg }}{{ . }}{{ end }}
                                {{ .DisplayName }}
                            </span>
                        </a>
                        {{ end }}
                    </div>
                </div>
                <div class="hidden lg:block lg:flex-auto w-full h-full rounded-4xl
                    bg-(image:--bg-image-md) bg-cover bg-center"></div>
            </div>
        </div>
    </div>
</body>

</html>
