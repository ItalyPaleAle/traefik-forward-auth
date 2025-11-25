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

<body class="bg-gray-100 dark:bg-gray-900 h-dvh">
    <div class="
        bg-(image:--bg-image-md) md:bg-(image:--bg-image-lg) lg:bg-none
        bg-cover bg-center p-1 h-full">
        <div class="flex flex-row items-center justify-center flex-none h-full lg:block">
            <div class="flex flex-col lg:flex-row lg:h-full lg:bg-white rounded-xl lg:rounded-r-4xl lg:rounded-l-md backdrop-blur-sm lg:backdrop-blur-none bg-white/90 dark:bg-gray-800/85">
                <div class="flex flex-col items-center justify-center flex-none px-10 py-6 space-y-2 md:py-8 md:px-14 lg:basis-2xl">
                    <h1 class="pb-2 text-2xl text-gray-900 dark:text-white md:text-3xl md:pb-4">{{ .Title }}</h1>
                    <p class="w-full p-4 font-medium text-center text-gray-900 bg-white rounded-lg dark:bg-gray-900 dark:text-white">You're authenticated with provider <b><code>{{ .Provider }}</code></b> as <b><code>{{ .User }}</code></b>.</p>
                    <a href="{{ .LogoutUrl }}" class="p-0.5 text-sm font-medium rounded-lg group bg-gradient-to-br red-to-yellow mt-2 md:mt-4">
                        <span class="relative text-xs md:text-sm w-full inline-flex items-center px-1.5 py-1 md:px-3 md:py-1.5 transition-all ease-in duration-75 bg-white dark:bg-gray-900 rounded-md group-hover:bg-transparent group-hover:dark:bg-transparent">
                            Log out
                        </span>
                    </a>
                </div>
                <div class="hidden lg:block lg:flex-auto w-full h-full rounded-4xl
                    bg-(image:--bg-image-md) bg-cover bg-center"></div>
            </div>
        </div>
    </div>
</body>

</html>
