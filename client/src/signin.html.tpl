<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <title>{{ .Title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{{ .BaseUrl }}/style.css">
</head>

<body class="bg-gray-100 dark:bg-gray-900 h-dvh">
    <div class="
        bg-(image:--bg-image-md) md:bg-(image:--bg-image-lg) lg:bg-none
        bg-cover bg-center p-1 h-full">
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
