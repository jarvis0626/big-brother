"""Rasterize original eye geometry using Pillow; SVG remains the master vector."""
from pathlib import Path
from PIL import Image, ImageDraw
root = Path(__file__).resolve().parents[1]
assets = root / 'assets'
assets.mkdir(exist_ok=True)
scale = 4
image = Image.new('RGBA', (256 * scale, 256 * scale))
d = ImageDraw.Draw(image)
d.rounded_rectangle((8*scale, 8*scale, 248*scale, 248*scale), radius=60*scale, fill='#14161b')
def point(t, a, b, c, e):
    return ((1-t)**3*a[0]+3*(1-t)**2*t*b[0]+3*(1-t)*t*t*c[0]+t**3*e[0], (1-t)**3*a[1]+3*(1-t)**2*t*b[1]+3*(1-t)*t*t*c[1]+t**3*e[1])
curve=[]
for a,b,c,e in [((38,128),(60,94),(91,76),(128,76)),((128,76),(165,76),(196,94),(218,128)),((218,128),(196,162),(165,180),(128,180)),((128,180),(91,180),(60,162),(38,128))]:
    curve += [(x*scale,y*scale) for x,y in (point(i/32,a,b,c,e) for i in range(33))]
d.line(curve, fill='#eeebea', width=13*scale, joint='curve')
d.ellipse((101*scale,101*scale,155*scale,155*scale),fill='#c55258')
d.ellipse((118*scale,118*scale,138*scale,138*scale),fill='#14161b')
image = image.resize((256,256),Image.Resampling.LANCZOS)
image.save(assets/'icon.png')
image.save(assets/'icon.ico',format='ICO',sizes=[(16,16),(20,20),(24,24),(32,32),(40,40),(48,48),(64,64),(128,128),(256,256)])
for size in (16,24,32,48): image.resize((size,size),Image.Resampling.LANCZOS).save(assets/f'tray-{size}.png')
print('Original vector and Windows icons ready')
