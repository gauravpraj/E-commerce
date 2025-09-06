from django.shortcuts import render, get_object_or_404
from .models import Product
from category.models import Category
from django.http import HttpResponse
from carts.models import CartItem
from carts.views import _cart_id
from django.core.paginator import PageNotAnInteger, EmptyPage ,Paginator
from django.db.models import Q

# Create your views here.

def store(request, category_slug=None):
    categories = None
    products = None
    if category_slug != None:
        categories = get_object_or_404(Category, slug=category_slug)
        products = Product.objects.filter(category=categories, is_available=True).order_by('product_name')
        product_count = products.count()
        
        # pagination
        paginator = Paginator(products , 6)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
    else:  
        products = Product.objects.all().filter(is_available=True).order_by('product_name')
        product_count = products.count()
        
        # pagination
        paginator = Paginator(products , 2)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
    context = {
        'products' : paged_products,
        'product_count' : product_count,
    }
    return render(request , 'store/store.html',context)
    
def product_detail(request , category_slug , product_slug ):
    product=Product.objects.get(category__slug=category_slug,slug=product_slug)
    in_cart = CartItem.objects.filter(cart__cart_id = _cart_id(request) , product=product).exists()
    
    context = {
        'product' : product,
        'in_cart' : in_cart,
    }
    return render(request , 'store/product_detail.html' , context)


def search(request):
    if request.method == 'GET':
        keyword = request.GET['keyword']
        print(f"\n\n\n\t--------------> 51 keyword",keyword)
        if keyword:
            products = Product.objects.filter(Q(product_name__icontains = keyword) | Q(description__icontains = keyword))
            product_count = products.count()
            context = {
                'products' : products,
                'product_count' : product_count,
            }
    return render(request,'store/store.html' , context)